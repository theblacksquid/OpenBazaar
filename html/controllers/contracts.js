/**
 * Contracts controller.
 *
 * @desc This controller is the contracts controller.
 * @param {!angular.Scope} $scope
 * @constructor
 */
angular.module('app')
    .controller('Contracts', ['$scope', '$interval', '$routeParams', '$location', 'Connection',
        function($scope, $interval, $routeParams, $location, Connection) {

            $scope.contractsPanel = true;
            $scope.path = $location.path();
            $scope.$emit('sidebar', false);

            /**
             * Establish message handlers
             * @msg - message from websocket to pass on to handler
             */
            var listeners = Connection.$$listeners;

            Connection.$on('load_page', function(e, msg){ $scope.load_page(msg); });
            Connection.$on('contracts', function(e, msg){ $scope.parse_contracts(msg); });
            Connection.$on('btc_ticker', function(e, msg){ $scope.parse_btc_ticker(msg); });

            $scope.load_page = function(msg) {
                console.log($scope.path);
                $scope.sidebar = false;
                $scope.queryContracts();
            };

            $scope.queryContracts = function() {
                var query = { 'type': 'query_contracts' };
                Connection.send('query_contracts', query);
            };

            $scope.parse_btc_ticker = function(msg) {
                var data = JSON.parse(msg.data);
                console.log('BTC Ticker', data.USD);
                $scope.last_price_usd = data.USD.last;
            };

            $scope.undoRemoveContract = function(contract_id) {
                Connection.send("undo_remove_contract", {
                    "contract_id": contract_id
                });
                $scope.undo_remove = null;
                Connection.send("query_contracts", {});
                if (!$scope.$$phase) {
                    $scope.$apply();
                }
            };

            $scope.removeContract = function(contract_id) {
                $('#contract-row-'+contract_id).fadeOut({ "duration": 1000 });
                $scope.undo_remove = true;
                $scope.undo_contract_id = contract_id;
                Connection.send("remove_contract", {
                    "contract_id": contract_id
                });
                Connection.send("query_contracts", {});
                if (!$scope.$$phase) {
                    $scope.$apply();
                }
            };

            $scope.republishContracts = function() {
                Connection.send("republish_contracts", {});
                Connection.send("query_contracts", {});
            };

            $scope.ProductModal = function($scope, $modal, $log) {

                $scope.contracts_page_changed = function() {
                    console.log($scope.contracts_current_page);
                    var query = {
                        'page': $scope.contracts_current_page - 1
                    };
                    console.log(query);
                    Connection.send('query_contracts', query);

                };

                $scope.open = function(size, backdrop) {

                    backdrop = backdrop ? backdrop : true;

                    $scope.edit = false;

                    var modalInstance = $modal.open({
                        templateUrl: 'partials/modal/addContract.html',
                        controller: $scope.ProductModalInstance,
                        size: size,
                        backdrop: backdrop,
                        resolve: {
                            contract: function() {
                                return {
                                    "contract": $scope.contract
                                };
                            },
                            edit: function() {
                                return false;
                            },
                            scope: function() {
                                return $scope;
                            }
                        }
                    });

                    modalInstance.result.then(function(selectedItem) {
                        $scope.selected = selectedItem;
                    }, function() {
                        $log.info('Product modal dismissed at: ' + new Date());
                    });

                };

                $scope.editContract = function(contract) {
                    console.log('Editing Contract #' + contract.id);
                    console.log(contract);
                    backdrop = true;
                    size = 'lg';
                    $scope.edit = true;

                    var modalInstance = $modal.open({
                        templateUrl: 'partials/modal/addContract.html',
                        controller: $scope.ProductModalInstance,
                        size: size,
                        backdrop: backdrop,
                        resolve: {
                            contract: function() {
                                return {
                                    "contract": contract
                                };
                            },
                            edit: function() {
                                return true;
                            },
                            scope: function() {
                                return $scope;
                            }
                        }
                    });

                    modalInstance.result.then(function(selectedItem) {
                        $scope.selected = selectedItem;
                    }, function() {
                        $log.info('Product modal dismissed at: ' + new Date());
                    });
                };

            };

            $scope.ProductModalInstance = function($scope, $modalInstance, contract, edit, scope) {

                console.log('Last USD Price: ', scope.$parent.last_price_usd);

                if(edit) {
                    contract = contract.contract;
                    $scope.contract = contract;
                    $scope.contract.id = contract.id;
                    $scope.contract.productQuantity = contract.item_quantity_available;
                    $scope.contract.productCondition = contract.item_condition;
                    $scope.contracts_current_page = 0;
                    $scope.contract.productPrice = contract.unit_price;
                    $scope.contract.productShippingPrice = contract.shipping_price;
                    $scope.contract.productTitle = contract.item_title;
                    $scope.contract.productDescription = contract.item_desc;
                    $scope.contract.productImage = contract.item_images;
                    $scope.contract.remoteImages = contract.item_remote_images;
                    $scope.edit = true;

                } else {
                    $scope.contract = contract;
                    $scope.contract.id = '';
                    $scope.contract.productQuantity = 1;
                    $scope.contract.productCondition = 'New';
                    $scope.contracts_current_page = 0;
                    $scope.contract.productPrice = 0.5;
                    $scope.contract.productShippingPrice = 0;
                    $scope.contract.remoteImages = [];
                    $scope.edit = false;
                    $scope.last_price_usd = scope.$parent.last_price_usd;
                }

                console.log($scope.contract);

                $scope.saveContract = function() {

                    $scope.contract.productPrice = (String($scope.contract.productPrice).match(/^[+]?([0-9]+(?:[\.][0-9]*)?|\.[0-9]+)$/)) ? $scope.contract.productPrice : 0;
                    $scope.contract.productShippingPrice = (String($scope.contract.productShippingPrice).match(/^[+]?([0-9]+(?:[\.][0-9]*)?|\.[0-9]+)$/)) ? $scope.contract.productShippingPrice : 0;

                    if (contract.contract) {

                        // Imported JSON format contract
                        var jsonContract = $scope.contract.rawText;
                        console.log(jsonContract);

                        Connection.send("import_raw_contract", {
                            'contract': jsonContract
                        });

                    } else {

                        contract = {};
                        contract.Contract_Metadata = {
                            "OBCv": "0.4",
                            "category": "physical_goods",
                            "subcategory": "fixed_price",
                            "contract_nonce": "01",
                            "expiration": "2014-01-01 00:00:00"
                        };
                        contract.Seller = {
                            "seller_GUID": "",
                            "seller_BTC_uncompressed_pubkey": "",
                            "seller_PGP": ""
                        };
                        contract.Contract = {
                            "item_title": $scope.contract.productTitle,
                            "item_keywords": [],
                            "currency": "XBT",
                            "item_price": $scope.contract.productPrice,
                            "item_condition": $scope.contract.productCondition,
                            "item_quantity": $scope.contract.productQuantity,
                            "item_desc": $scope.contract.productDescription,
                            "item_images": {},
                            "item_remote_images": [],
                            "item_delivery": {
                                "countries": "",
                                "region": "",
                                "est_delivery": "",
                                "shipping_price": $scope.contract.productShippingPrice
                            }
                        };

                        var keywords = ($scope.contract.productKeywords) ? $scope.contract.productKeywords.split(',') : [];
                        $.each(keywords, function(i, el) {
                            if ($.inArray(el.trim(), contract.Contract.item_keywords) === -1 && el.trim() !== '') {
                                contract.Contract.item_keywords.push(el.trim());
                            }
                        });

                        image_thumb = document.getElementById('image-thumb');
                        if(image_thumb) {
                            console.log(image_thumb);
                            product_image = image_thumb.src;
                            contract.Contract.item_images.image1 = product_image;
                        }

                        var remote_images = [];
                        if($scope.contract.imageURL1 !== '' && $scope.contract.imageURL1 !== undefined) {
                            remote_images.push($scope.contract.imageURL1);
                        }
                        if($scope.contract.imageURL2 !== '' && $scope.contract.imageURL2 !== undefined) {
                            remote_images.push($scope.contract.imageURL2);
                        }
                        if($scope.contract.imageURL3 !== '' && $scope.contract.imageURL3 !== undefined) {
                            remote_images.push($scope.contract.imageURL3);
                        }
                        contract.Contract.item_remote_images = remote_images;

                        console.log('Contract: ', contract);
                        Connection.send("create_contract", contract);
                        Notifier.success('Success', 'Contract saved successfully.');
                        Connection.send("query_contracts", {});


                    }
                    $modalInstance.dismiss('cancel');
                };

                $scope.cancel = function() {
                    Connection.send("query_contracts", {});
                    $modalInstance.dismiss('cancel');
                };

                $scope.toggleItemAdvanced = function() {
                    $scope.itemAdvancedDetails = ($scope.itemAdvancedDetails) ? 0 : 1;
                };

            };

            if (Connection.websocket.readyState == 1) {
                $scope.load_page({});
            }

        }
    ]);
