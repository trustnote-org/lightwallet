'use strict'

var async = require('async');
var balances = require('./balances');
var network = require('./network.js');
var conf = require('./conf.js');
var ValidationUtils = require("./validation_utils.js");
var db = require('./db.js');
var mutex = require('./mutex.js');
var storage = require('./storage.js');
var composer = require('./composer.js');
var _ = require('lodash');
var divisibleAsset = require('./divisible_asset.js');
var constants = require('./constants.js');
var objectHash = require('./object_hash.js');
var device = require('./device.js');



function findAddress(address, signing_path, callbacks, fallback_remote_device_address){
    db.query(
        "SELECT wallet, account, is_change, address_index, full_approval_date, device_address \n\
        FROM my_addresses JOIN wallets USING(wallet) JOIN wallet_signing_paths USING(wallet) \n\
        WHERE address=? AND signing_path=?",
        [address, signing_path],
        function(rows){
            if (rows.length > 1)
                throw Error("more than 1 address found");
            if (rows.length === 1){
                var row = rows[0];
                if (!row.full_approval_date)
                    return callbacks.ifError("wallet of address "+address+" not approved");
                if (row.device_address !== device.getMyDeviceAddress())
                    return callbacks.ifRemote(row.device_address);
                var objAddress = {
                    address: address,
                    wallet: row.wallet,
                    account: row.account,
                    is_change: row.is_change,
                    address_index: row.address_index
                };
                callbacks.ifLocal(objAddress);
                return;
            }
            db.query(
            //  "SELECT address, device_address, member_signing_path FROM shared_address_signing_paths WHERE shared_address=? AND signing_path=?", 
                // look for a prefix of the requested signing_path
                "SELECT address, device_address, signing_path FROM shared_address_signing_paths \n\
                WHERE shared_address=? AND signing_path=SUBSTR(?, 1, LENGTH(signing_path))", 
                [address, signing_path],
                function(sa_rows){
                    if (rows.length > 1)
                        throw Error("more than 1 member address found for shared address "+address+" and signing path "+signing_path);
                    if (sa_rows.length === 0){
                        if (fallback_remote_device_address)
                            return callbacks.ifRemote(fallback_remote_device_address);
                        return callbacks.ifUnknownAddress();
                    }
                    var objSharedAddress = sa_rows[0];
                    var relative_signing_path = 'r' + signing_path.substr(objSharedAddress.signing_path.length);
                    var bLocal = (objSharedAddress.device_address === device.getMyDeviceAddress()); // local keys
                    if (objSharedAddress.address === '')
                        return callbacks.ifMerkle(bLocal);
                    findAddress(objSharedAddress.address, relative_signing_path, callbacks, bLocal ? null : objSharedAddress.device_address);
                }
            );
        }
    );
}


// returns assoc array signing_path => (key|merkle)
function readFullSigningPaths(conn, address, arrSigningDeviceAddresses, handleSigningPaths){
    
    var assocSigningPaths = {};
    
    function goDeeper(member_address, path_prefix, onDone){
        // first, look for wallet addresses
        var sql = "SELECT signing_path FROM my_addresses JOIN wallet_signing_paths USING(wallet) WHERE address=?";
        var arrParams = [member_address];
        if (arrSigningDeviceAddresses && arrSigningDeviceAddresses.length > 0){
            sql += " AND device_address IN(?)";
            arrParams.push(arrSigningDeviceAddresses);
        }
        conn.query(sql, arrParams, function(rows){
            rows.forEach(function(row){
                assocSigningPaths[path_prefix + row.signing_path.substr(1)] = 'key';
            });
            if (rows.length > 0)
                return onDone();
            // next, look for shared addresses, and search from there recursively
            sql = "SELECT signing_path, address FROM shared_address_signing_paths WHERE shared_address=?";
            arrParams = [member_address];
            if (arrSigningDeviceAddresses && arrSigningDeviceAddresses.length > 0){
                sql += " AND device_address IN(?)";
                arrParams.push(arrSigningDeviceAddresses);
            }
            conn.query(sql, arrParams, function(rows){
                if(rows.length > 0) {
                    async.eachSeries(
                        rows,
                        function (row, cb) {
                            if (row.address === '') { // merkle
                                assocSigningPaths[path_prefix + row.signing_path.substr(1)] = 'merkle';
                                return cb();
                            }

                            goDeeper(row.address, path_prefix + row.signing_path.substr(1), cb);
                        },
                        onDone
                    );
                } else {
                    assocSigningPaths[path_prefix] = 'key';
                    onDone();
                }
            });
        });
    }
    
    goDeeper(address, 'r', function(){
        handleSigningPaths(assocSigningPaths); // order of signing paths is not significant
    });
}


function readAdditionalSigningAddresses(arrPayingAddresses, arrSigningAddresses, arrSigningDeviceAddresses, handleAdditionalSigningAddresses){
    var arrFromAddresses = arrPayingAddresses.concat(arrSigningAddresses);
    var sql = "SELECT DISTINCT address FROM shared_address_signing_paths \n\
        WHERE shared_address IN(?) \n\
            AND ( \n\
                EXISTS (SELECT 1 FROM my_addresses WHERE my_addresses.address=shared_address_signing_paths.address) \n\
                OR \n\
                EXISTS (SELECT 1 FROM shared_addresses WHERE shared_addresses.shared_address=shared_address_signing_paths.address) \n\
            ) \n\
            AND ( \n\
                NOT EXISTS (SELECT 1 FROM addresses WHERE addresses.address=shared_address_signing_paths.address) \n\
                OR ( \n\
                    SELECT definition \n\
                    FROM address_definition_changes CROSS JOIN units USING(unit) LEFT JOIN definitions USING(definition_chash) \n\
                    WHERE address_definition_changes.address=shared_address_signing_paths.address AND is_stable=1 AND sequence='good' \n\
                    ORDER BY level DESC LIMIT 1 \n\
                ) IS NULL \n\
            )";
    var arrParams = [arrFromAddresses];
    if (arrSigningAddresses.length > 0){
        sql += " AND address NOT IN(?)";
        arrParams.push(arrSigningAddresses);
    }
    if (arrSigningDeviceAddresses && arrSigningDeviceAddresses.length > 0){
        sql += " AND device_address IN(?)";
        arrParams.push(arrSigningDeviceAddresses);
    }
    db.query(
        sql, 
        arrParams,
        function(rows){
            var arrAdditionalAddresses = rows.map(function(row){ return row.address; });
            if (arrAdditionalAddresses.length === 0)
                return handleAdditionalSigningAddresses([]);
            readAdditionalSigningAddresses([], arrSigningAddresses.concat(arrAdditionalAddresses), arrSigningDeviceAddresses, function(arrMoreAddresses){
                handleAdditionalSigningAddresses(arrAdditionalAddresses.concat(arrMoreAddresses));
            });
        }
    );
}


function determineIfFixedDenominations(asset, handleResult){
    if (!asset)
        return handleResult(false);
    storage.readAsset(db, asset, null, function(err, objAsset){
        if (err)
            throw Error(err);
        handleResult(objAsset.fixed_denominations);
    });
}


function readBalance(wallet, handleBalance){
    balances.readBalance(wallet, function(assocBalances) {
        handleBalance(assocBalances);
        if (conf.bLight){ // make sure we have all asset definitions available
            var arrAssets = Object.keys(assocBalances).filter(function(asset){ return (asset !== 'base'); });
            if (arrAssets.length === 0)
                return;
            network.requestProofsOfJointsIfNewOrUnstable(arrAssets);
        }
    });
}



function sendPaymentFromWallet(
        asset, wallet, to_address, amount, change_address, arrSigningDeviceAddresses, recipient_device_address, signWithLocalPrivateKey, handleResult)
{
    sendMultiPayment({
        asset: asset,
        wallet: wallet,
        to_address: to_address,
        amount: amount,
        change_address: change_address,
        arrSigningDeviceAddresses: arrSigningDeviceAddresses,
        recipient_device_address: recipient_device_address,
        signWithLocalPrivateKey: signWithLocalPrivateKey
    }, handleResult);
}


function sendMultiPayment(opts, handleResult)
{
    var asset = opts.asset;
    if (asset === 'base')
        asset = null;
    var wallet = opts.wallet;
    var arrPayingAddresses = opts.paying_addresses;
    var fee_paying_wallet = opts.fee_paying_wallet;
    var arrSigningAddresses = opts.signing_addresses || [];
    var to_address = opts.to_address;
    var amount = opts.amount;
    var bSendAll = opts.send_all;
    var change_address = opts.change_address;
    var arrSigningDeviceAddresses = opts.arrSigningDeviceAddresses;
    var recipient_device_address = opts.recipient_device_address;
    var signWithLocalPrivateKey = opts.signWithLocalPrivateKey;
    var merkle_proof = opts.merkle_proof;
    
    var base_outputs = opts.base_outputs;
    var asset_outputs = opts.asset_outputs;
    var messages = opts.messages;
    
    if (!wallet && !arrPayingAddresses)
        throw Error("neither wallet id nor paying addresses");
    if (wallet && arrPayingAddresses)
        throw Error("both wallet id and paying addresses");
    if ((to_address || amount) && (base_outputs || asset_outputs))
        throw Error('to_address and outputs at the same time');
    if (!asset && asset_outputs)
        throw Error('base asset and asset outputs');
    if (amount){
        if (typeof amount !== 'number')
            throw Error('amount must be a number');
        if (amount < 0)
            throw Error('amount must be positive');
    }
    
    var estimated_amount = amount;
    if (!estimated_amount && asset_outputs)
        estimated_amount = asset_outputs.reduce(function(acc, output){ return acc+output.amount; }, 0);
    if (estimated_amount && !asset)
        estimated_amount += TYPICAL_FEE;
    
    readFundedAndSigningAddresses(
        asset, wallet || arrPayingAddresses, estimated_amount, fee_paying_wallet, arrSigningAddresses, arrSigningDeviceAddresses, 
        function(arrFundedAddresses, arrBaseFundedAddresses, arrAllSigningAddresses){
        
            if (arrFundedAddresses.length === 0)
                return handleResult("There are no funded addresses");
            if (asset && arrBaseFundedAddresses.length === 0)
                return handleResult("No notes to pay fees");

            var bRequestedConfirmation = false;
            var signer = {
                readSigningPaths: function(conn, address, handleLengthsBySigningPaths){ // returns assoc array signing_path => length
                    readFullSigningPaths(conn, address, arrSigningDeviceAddresses, function(assocTypesBySigningPaths){
                        var assocLengthsBySigningPaths = {};
                        for (var signing_path in assocTypesBySigningPaths){
                            var type = assocTypesBySigningPaths[signing_path];
                            if (type === 'key')
                                assocLengthsBySigningPaths[signing_path] = constants.SIG_LENGTH;
                            else if (type === 'merkle'){
                                if (merkle_proof)
                                    assocLengthsBySigningPaths[signing_path] = merkle_proof.length;
                            }
                            else
                                throw Error("unknown type "+type+" at "+signing_path);
                        }
                        handleLengthsBySigningPaths(assocLengthsBySigningPaths);
                    });
                },
                readDefinition: function(conn, address, handleDefinition){
                    conn.query(
                        "SELECT definition FROM my_addresses WHERE address=? UNION SELECT definition FROM shared_addresses WHERE shared_address=?", 
                        [address, address], 
                        function(rows){
                            if (rows.length !== 1)
                                throw Error("definition not found");
                            handleDefinition(null, JSON.parse(rows[0].definition));
                        }
                    );
                },
                sign: function(objUnsignedUnit, assocPrivatePayloads, address, signing_path, handleSignature){
                    var buf_to_sign = objectHash.getUnitHashToSign(objUnsignedUnit);
                    findAddress(address, signing_path, {
                        ifError: function(err){
                            throw Error(err);
                        },
                        ifUnknownAddress: function(err){
                            throw Error("unknown address "+address+" at "+signing_path);
                        },
                        ifLocal: function(objAddress){
                            signWithLocalPrivateKey(objAddress.wallet, objAddress.account, objAddress.is_change, objAddress.address_index, buf_to_sign, function(sig){
                                handleSignature(null, sig);
                            });
                        },
                        ifRemote: function(device_address){
                            // we'll receive this event after the peer signs
                            eventBus.once("signature-"+device_address+"-"+address+"-"+signing_path+"-"+buf_to_sign.toString("base64"), function(sig){
                                handleSignature(null, sig);
                                if (sig === '[refused]')
                                    eventBus.emit('refused_to_sign', device_address);
                            });
                            walletGeneral.sendOfferToSign(device_address, address, signing_path, objUnsignedUnit, assocPrivatePayloads);
                            if (!bRequestedConfirmation){
                                eventBus.emit("confirm_on_other_devices");
                                bRequestedConfirmation = true;
                            }
                        },
                        ifMerkle: function(bLocal){
                            if (!bLocal)
                                throw Error("merkle proof at path "+signing_path+" should be provided by another device");
                            if (!merkle_proof)
                                throw Error("merkle proof at path "+signing_path+" not provided");
                            handleSignature(null, merkle_proof);
                        }
                    });
                }
            };

            var params = {
                available_paying_addresses: arrFundedAddresses, // forces 'minimal' for payments from shared addresses too, it doesn't hurt
                signing_addresses: arrAllSigningAddresses,
                messages: messages, 
                signer: signer, 
                callbacks: {
                    ifNotEnoughFunds: function(err){
                        handleResult(err);
                    },
                    ifError: function(err){
                        handleResult(err);
                    },
                    // for asset payments, 2nd argument is array of chains of private elements
                    // for base asset, 2nd argument is assocPrivatePayloads which is null
                    ifOk: function(objJoint, arrChainsOfRecipientPrivateElements, arrChainsOfCosignerPrivateElements){
                        //light wallet do not broadcastJonit, do postJointToLightVendor
                        // network.broadcastJoint(objJoint);
                        if (!arrChainsOfRecipientPrivateElements && recipient_device_address) // send notification about public payment
                            walletGeneral.sendPaymentNotification(recipient_device_address, objJoint.unit.unit);
                        handleResult(null, objJoint.unit.unit);
                    }
                }
            };

            // Victor ShareAddress 
            if (opts.arrDefinition && opts.assocSignersByPath)
                params.arrShareDefinition = [{"arrDefinition":opts.arrDefinition, "assocSignersByPath":opts.assocSignersByPath}];
            
            if (asset){
                if (bSendAll)
                    throw Error('send_all with asset');
                params.asset = asset;
                params.available_fee_paying_addresses = arrBaseFundedAddresses;
                if (to_address){
                    params.to_address = to_address;
                    params.amount = amount; // in asset units
                }
                else{
                    params.asset_outputs = asset_outputs;
                    params.base_outputs = base_outputs; // only destinations, without the change
                }
                params.change_address = change_address;
                storage.readAsset(db, asset, null, function(err, objAsset){
                    if (err)
                        throw Error(err);
                //  if (objAsset.is_private && !recipient_device_address)
                //      return handleResult("for private asset, need recipient's device address to send private payload to");
                    if (objAsset.is_private){
                        // save messages in outbox before committing
                        params.callbacks.preCommitCb = function(conn, arrChainsOfRecipientPrivateElements, arrChainsOfCosignerPrivateElements, cb){
                            if (!arrChainsOfRecipientPrivateElements || !arrChainsOfCosignerPrivateElements)
                                throw Error('no private elements');
                            var sendToRecipients = function(cb2){
                                if (recipient_device_address)
                                    walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, false, conn, cb2);
                                else // paying to another wallet on the same device
                                    forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChainsOfRecipientPrivateElements, conn, cb2);
                            };
                            var sendToCosigners = function(cb2){
                                if (wallet)
                                    walletDefinedByKeys.forwardPrivateChainsToOtherMembersOfWallets(arrChainsOfCosignerPrivateElements, [wallet], conn, cb2);
                                else // arrPayingAddresses can be only shared addresses
                                    walletDefinedByAddresses.forwardPrivateChainsToOtherMembersOfAddresses(arrChainsOfCosignerPrivateElements, arrPayingAddresses, conn, cb2);
                            };
                            async.series([sendToRecipients, sendToCosigners], cb);
                        };
                    }
                    if (objAsset.fixed_denominations){ // indivisible
                        params.tolerance_plus = 0;
                        params.tolerance_minus = 0;
                        indivisibleAsset.composeAndSaveMinimalIndivisibleAssetPaymentJoint(params);
                    }
                    else{ // divisible
                        // if(opts.candyOutput && opts.candyOutput.length > 1) {
                        if(opts.candyOutput) {
                            params.base_outputs = opts.candyOutput;
                        }
                        divisibleAsset.composeAndSaveMinimalDivisibleAssetPaymentJoint(params);
                    }
                });
            }
            else{ // base asset
                if (bSendAll){
                    params.send_all = bSendAll;
                    params.outputs = [{address: to_address, amount: 0}];
                }
                else{
                    params.outputs = to_address ? [{address: to_address, amount: amount}] : (base_outputs || []);
                    if(opts.candyOutput && opts.candyOutput.length > 1) {
                        params.outputs = opts.candyOutput;
                    }
                    params.outputs.push({address: change_address, amount: 0});
                }
                composer.composeAndSaveMinimalJoint(params);
            }

        }
    );
}



var TYPICAL_FEE = 1000;

// fee_paying_wallet is used only if there are no bytes on the asset wallet, it is a sort of fallback wallet for fees
function readFundedAndSigningAddresses(
        asset, wallet, estimated_amount, fee_paying_wallet, arrSigningAddresses, arrSigningDeviceAddresses, handleFundedAndSigningAddresses)
{
    readFundedAddresses(asset, wallet, estimated_amount, function(arrFundedAddresses){
        if (arrFundedAddresses.length === 0)
            return handleFundedAndSigningAddresses([], [], []);
        var arrBaseFundedAddresses = [];
        var addSigningAddressesAndReturn = function(){
            var arrPayingAddresses = _.union(arrFundedAddresses, arrBaseFundedAddresses);
            readAdditionalSigningAddresses(arrPayingAddresses, arrSigningAddresses, arrSigningDeviceAddresses, function(arrAdditionalAddresses){
                handleFundedAndSigningAddresses(arrFundedAddresses, arrBaseFundedAddresses, arrSigningAddresses.concat(arrAdditionalAddresses));
            });
        };
        if (!asset)
            return addSigningAddressesAndReturn();
        readFundedAddresses(null, wallet, TYPICAL_FEE, function(_arrBaseFundedAddresses){
            // fees will be paid from the same addresses as the asset
            if (_arrBaseFundedAddresses.length > 0 || !fee_paying_wallet || fee_paying_wallet === wallet){
                arrBaseFundedAddresses = _arrBaseFundedAddresses;
                return addSigningAddressesAndReturn();
            }
            readFundedAddresses(null, fee_paying_wallet, TYPICAL_FEE, function(_arrBaseFundedAddresses){
                arrBaseFundedAddresses = _arrBaseFundedAddresses;
                addSigningAddressesAndReturn();
            });
        });
    });
}


function readFundedAddresses(asset, wallet, estimated_amount, handleFundedAddresses){
    var walletIsAddresses = ValidationUtils.isNonemptyArray(wallet);
    if (walletIsAddresses)
        return composer.readSortedFundedAddresses(asset, wallet, estimated_amount, handleFundedAddresses);
    if (estimated_amount && typeof estimated_amount !== 'number')
        throw Error('invalid estimated amount: '+estimated_amount);
    // addresses closest to estimated amount come first
    var order_by = estimated_amount ? "(SUM(amount)>"+estimated_amount+") DESC, ABS(SUM(amount)-"+estimated_amount+") ASC" : "SUM(amount) DESC";
    db.query(
        "SELECT address, SUM(amount) AS total \n\
        FROM outputs JOIN my_addresses USING(address) \n\
        CROSS JOIN units USING(unit) \n\
        WHERE wallet=? AND is_stable=1 AND sequence='good' AND is_spent=0 AND "+(asset ? "asset=?" : "asset IS NULL")+" \n\
            AND NOT EXISTS ( \n\
                SELECT * FROM unit_authors JOIN units USING(unit) \n\
                WHERE is_stable=0 AND unit_authors.address=outputs.address AND definition_chash IS NOT NULL \n\
            ) \n\
        GROUP BY address ORDER BY "+order_by,
        asset ? [wallet, asset] : [wallet],
        function(rows){
            determineIfFixedDenominations(asset, function(bFixedDenominations){
                if (bFixedDenominations)
                    estimated_amount = 0; // don't shorten the list of addresses, indivisible_asset.js will do it later according to denominations
                handleFundedAddresses(composer.filterMostFundedAddresses(rows, estimated_amount));
            });
            /*if (arrFundedAddresses.length === 0)
                return handleFundedAddresses([]);
            if (!asset)
                return handleFundedAddresses(arrFundedAddresses);
            readFundedAddresses(null, wallet, function(arrBytesFundedAddresses){
                handleFundedAddresses(_.union(arrFundedAddresses, arrBytesFundedAddresses));
            });*/
        }
    );
}

function readTransactionHistory(opts, handleHistory){
    var asset = opts.asset;
    if (opts.wallet && opts.address || !opts.wallet && !opts.address)
        throw Error('invalid wallet and address params');
    var wallet = opts.wallet || opts.address;
    var walletIsAddress = ValidationUtils.isValidAddress(wallet);
    var join_my_addresses = walletIsAddress ? "" : "JOIN my_addresses USING(address)";
    var where_condition = walletIsAddress ? "address=?" : "wallet=?";
    var asset_condition = (asset && asset !== "base") ? "asset="+db.escape(asset) : "asset IS NULL";
    var cross = "";
    if (opts.unit)
        where_condition += " AND unit="+db.escape(opts.unit);
    else if (opts.since_mci && ValidationUtils.isNonnegativeInteger(opts.since_mci)){
        where_condition += " AND main_chain_index>="+opts.since_mci;
        cross = "CROSS";
    }
    db.query(
        "SELECT unit, level, is_stable, sequence, address, \n\
            "+db.getUnixTimestamp("units.creation_date")+" AS ts, headers_commission+payload_commission AS fee, \n\
            SUM(amount) AS amount, address AS to_address, NULL AS from_address, main_chain_index AS mci \n\
        FROM units "+cross+" JOIN outputs USING(unit) "+join_my_addresses+" \n\
        WHERE "+where_condition+" AND "+asset_condition+" \n\
        GROUP BY unit, address \n\
        UNION \n\
        SELECT unit, level, is_stable, sequence, address, \n\
            "+db.getUnixTimestamp("units.creation_date")+" AS ts, headers_commission+payload_commission AS fee, \n\
            NULL AS amount, NULL AS to_address, address AS from_address, main_chain_index AS mci \n\
        FROM units "+cross+" JOIN inputs USING(unit) "+join_my_addresses+" \n\
        WHERE "+where_condition+" AND "+asset_condition+" \n\
        ORDER BY ts DESC"+(opts.limit ? " LIMIT ?" : ""),
        opts.limit ? [wallet, wallet, opts.limit] : [wallet, wallet],
        function(rows){
            var assocMovements = {};
            for (var i=0; i<rows.length; i++){
                var row = rows[i];
                //if (asset !== "base")
                //    row.fee = null;
                if (!assocMovements[row.unit])
                    assocMovements[row.unit] = {
                        plus:0, has_minus:false, ts: row.ts, level: row.level, is_stable: row.is_stable, sequence: row.sequence, fee: row.fee, mci: row.mci
                    };
                if (row.to_address){
                    assocMovements[row.unit].plus += row.amount;
                //  assocMovements[row.unit].my_address = row.to_address;
                    if (!assocMovements[row.unit].arrMyRecipients)
                        assocMovements[row.unit].arrMyRecipients = [];
                    assocMovements[row.unit].arrMyRecipients.push({my_address: row.to_address, amount: row.amount})
                }
                if (row.from_address)
                    assocMovements[row.unit].has_minus = true;
            }
        //  console.log(require('util').inspect(assocMovements));
            var arrTransactions = [];
            async.forEachOfSeries(
                assocMovements,
                function(movement, unit, cb){
                    if (movement.sequence !== 'good'){
                        var transaction = {
                            action: 'invalid',
                            confirmations: movement.is_stable,
                            unit: unit,
                            fee: movement.fee,
                            time: movement.ts,
                            level: movement.level,
                            mci: movement.mci
                        };
                        arrTransactions.push(transaction);
                        cb();
                    }
                    //绝大多数情况是 outputs表中的,
                    else if (movement.plus && !movement.has_minus){
                        // light clients will sometimes have input address = NULL
                        db.query(
                            "SELECT DISTINCT address FROM inputs WHERE unit=? AND "+asset_condition+" ORDER BY address", 
                            [unit], 
                            function(address_rows){
                                var arrPayerAddresses = address_rows.map(function(address_row){ return address_row.address; });
                                movement.arrMyRecipients.forEach(function(objRecipient){
                                    var transaction = {
                                        action: 'received',
                                        amount: objRecipient.amount,
                                        my_address: objRecipient.my_address,
                                        arrPayerAddresses: arrPayerAddresses,
                                        confirmations: movement.is_stable,
                                        unit: unit,
                                        fee: movement.fee,
                                        time: movement.ts,
                                        level: movement.level,
                                        mci: movement.mci
                                    };
                                    arrTransactions.push(transaction);
                                });
                                cb();
                            }
                        );
                    }
                    //都是 inputs 表中的 item
                    else if (movement.has_minus){
                        var queryString, parameters;
                        if(walletIsAddress){
                            queryString =   "SELECT address, SUM(amount) AS amount, (address!=?) AS is_external \n\
                                            FROM outputs \n\
                                            WHERE unit=? AND "+asset_condition+" \n\
                                            GROUP BY address";
                            parameters = [wallet, unit];
                        }
                        else {
                            queryString =   "SELECT outputs.address, SUM(amount) AS amount, (my_addresses.address IS NULL) AS is_external \n\
                                            FROM outputs \n\
                                            LEFT JOIN my_addresses ON outputs.address=my_addresses.address AND wallet=? \n\
                                            WHERE unit=? AND "+asset_condition+" \n\
                                            GROUP BY outputs.address";
                            parameters = [wallet, unit];
                        }
                        db.query(queryString, parameters, 
                            function(payee_rows){
                            	//is_external 为 1,证明 my_addresses.address is null, 表明这个地址在outputs表中有, 但是my_addresses表中没有, 这时为 sent
                            	//is_external 为 0,证明 outputs 和 my_addresses表中都有这个地址, 为 move,为自己一个钱包中的地址相互转账, 成为move,因为钱还在这个钱包中;
                                var action = payee_rows.some(function(payee){ return payee.is_external; }) ? 'sent' : 'moved';
                                for (var i=0; i<payee_rows.length; i++){
                                    var payee = payee_rows[i];
                                    if (action === 'sent' && !payee.is_external)
                                        continue;
                                    var transaction = {
                                        action: action,
                                        amount: payee.amount,
                                        addressTo: payee.address,
                                        confirmations: movement.is_stable,
                                        unit: unit,
                                        fee: movement.fee,
                                        time: movement.ts,
                                        level: movement.level,
                                        mci: movement.mci
                                    };
                                    if (action === 'moved')
                                        transaction.my_address = payee.address;
                                    arrTransactions.push(transaction);
                                }
                                cb();
                            }
                        );
                    }
                },
                function(){
                    arrTransactions.sort(function(a, b){
                        if (a.level < b.level)
                            return 1;
                        if (a.level > b.level)
                            return -1;
                        if (a.time < b.time)
                            return 1;
                        if (a.time > b.time)
                            return -1;
                        return 0;
                    });
                    arrTransactions.forEach(function(transaction){ transaction.asset = asset; });
                    handleHistory(arrTransactions);
                }
            );
        }
    );
}



exports.readBalance = readBalance;
exports.sendPaymentFromWallet = sendPaymentFromWallet;
exports.sendMultiPayment = sendMultiPayment;
exports.readTransactionHistory = readTransactionHistory;


/*
walletGeneral.readMyAddresses(function(arrAddresses){
    network.setWatchedAddresses(arrAddresses);
})
*/


/*
exports.sendSignature = sendSignature;
exports.readSharedBalance = readSharedBalance;
exports.readBalancesOnAddresses = readBalancesOnAddresses;
exports.readDeviceAddressesUsedInSigningPaths = readDeviceAddressesUsedInSigningPaths;
exports.determineIfDeviceCanBeRemoved = determineIfDeviceCanBeRemoved;
*/