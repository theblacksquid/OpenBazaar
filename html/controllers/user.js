/**
 * User controller.
 *
 * @desc This controller is the user controller.
 * @param {!angular.Scope} $scope
 * @constructor
 */
angular.module('app')
    .controller('User', ['$scope', '$interval', '$routeParams', '$location', '$rootScope', 'Connection', '$route', '$timeout',
        function($scope, $interval, $routeParams, $location, $rootScope, Connection, $route, $timeout) {

            $scope.page_loading = true;
            $scope.path = $location.path();

            $scope.$emit('sidebar', true);

            $scope.guid = $routeParams.userId;

            /**
             * Establish message handlers
             * @msg - message from websocket to pass on to handler
             */

            $scope.$evalAsync( function( $scope ) {


                    var listeners = Connection.$$listeners;

                    listeners.load_page = [];
                    Connection.$on('load_page', function(e, msg){ $scope.load_page(msg); });
                    listeners.store_contracts = [];
                    Connection.$on('store_contracts', function(e, msg){ $scope.parse_store_listings(msg); });
                    listeners.store_contract = [];
                    Connection.$on('store_contract', function(e, msg){ $scope.parse_store_contract(msg); });
                    listeners.page = [];
                    Connection.$on('page', function(e, msg){ $scope.parse_page(msg); });
                    Connection.$on('store_products', function(e, msg){ $scope.parse_store_products(msg); });
                    //if(!listeners.hasOwnProperty('new_listing')) {
                    //    Connection.$on('new_listing', function(e, msg){ $scope.parse_new_listing(msg); });
                    //}

                    listeners.no_listings_found = [];
                    Connection.$on('no_listings_found', function(e, msg){ $scope.handle_no_listings(); });

                    listeners.reputation_pledge_update = [];
                    Connection.$on('reputation_pledge_update', function(e, msg){ $scope.parse_reputation_pledge_update(msg); });

            });

            $scope.load_page = function(msg) {
                switch($scope.path) {

                    case "/user/"+$scope.guid+"/products":
                        $scope.queryShop($scope.guid);
                        $scope.store_listings = [];
                        $scope.storeProductsPanel = true;
                        $scope.showStorePanel('storeProducts');
                        break;
                    case "/user/"+$scope.guid+"/services":
                        $scope.queryShop($scope.guid);
                        $scope.storeServicesPanel = true;
                        $scope.showStorePanel('storeServices');
                        break;
                    default:
                        $scope.queryShop($scope.guid);
                        $scope.showStorePanel('storeInfo');
                }


            };

            $scope.parse_reputation_pledge_update = function(msg) {
                $scope.page.reputation_pledge = (msg.value) ? msg.value : 0;
            };

            $scope.compose_message = function(size, myself, address, subject) {
                $rootScope.$broadcast("compose_message", {
                    size: size,
                    myself: myself,
                    bm_address: address,
                    subject: subject
                });
            };

            $scope.compose_inbox_message = function(size, myself, guid, subject) {
                console.log('Composing Inbox Message');
                $rootScope.$broadcast("compose_inbox_message", {
                    size: size,
                    myself: myself,
                    guid: guid,
                    subject: subject
                });
            };

            /**
             * Query the network for a merchant and then
             * show the page
             * @guid - GUID of page to load
             */
            $scope.queryShop = function(guid) {

                $scope.awaitingShop = guid;

                console.log('Querying for shop: ', guid);

                // Tell the user store is probably offline if no response
                setTimeout(function() {
                    if($scope.page_loading) {
                        $scope.page_loading = false;
                        $scope.page_unreachable = true;
                        $scope.$apply();
                    }
                }, 15000);

                var query = {
                    'type': 'query_store_listings',
                    'findGUID': guid
                };

                Connection.send('query_page', query);

            };

            $scope.parse_page = function(msg) {

                console.log('scope', $scope);
                $scope.page_loading = false;

                console.log('Parsing Store Page: ', msg);

                msg.senderNick = msg.senderNick.substring(0, 120);
                msg.text = msg.text.substring(0, 2048);

                if (!$scope.reviews.hasOwnProperty(msg.pubkey)) {
                    $scope.reviews[msg.pubkey] = [];
                }

                $.each($scope.settings.notaries, function(idx, val) {
                    if (val.guid == msg.senderGUID) {
                       msg.isTrustedNotary = true;
                    }
                });

                if (!$scope.dashboard) {
                    $scope.currentReviews = $scope.reviews[msg.pubkey];
                    $scope.page = msg;
                    $scope.page.reputation_pledge = 0;

                    if(('subpanel' in $scope) && $scope.subpanel == 'listings') {
                        $scope.queryStoreProducts($scope.guid);
                    }

                }
                console.log($scope.page);

            };

            // A listing has shown up from the network
            $scope.store_listings = [];
            $scope.parse_new_listing = function(msg) {
                console.log(msg.data);
                var contract_data = msg.data;
                contract_data.key = msg.key;
                contract_data.rawContract = msg.rawContract;
                contract_data.nickname = msg.nickname;
                $scope.store_listings.push(contract_data);
                $scope.store_listings = jQuery.unique($scope.store_listings);
                $.each($scope.store_listings, function(index, contract) {
                    if (jQuery.isEmptyObject(contract.Contract.item_images)) {
                        console.log('empty object');
                        contract.Contract.item_images = "img/no-photo.png";
                    }
                });
                $('#listing-loader').hide();
                console.log('New Listing', $scope.store_listings);
                $scope.$apply();
                $scope.no_listings = false;
            };

            $scope.no_listings = null;
            $scope.handle_no_listings = function() {
                $('#listing-loader').hide();
                $scope.no_listings = true;
            };

            $scope.parse_store_contract = function(msg) {
                var contract = msg.contract;
                var contract_exists = false;

                $.each($scope.store_listings, function(i, listing) {
                    console.log(listing.key, msg.contract.key);
                    if(listing.key == msg.contract.key) {
                        contract_exists = true;
                    }
                });

                if('item_images' in contract) {
                    if (jQuery.isEmptyObject(contract.item_images)) {
                        contract.item_images = "img/no-photo.png";
                    }
                } else {
                    contract.item_images = "img/no-photo.png";
                }

                if(!contract_exists && $scope.guid == contract.senderGUID) {
                    $scope.store_listings.push(contract);
                }

                $('#listing-loader').hide();
                console.log('New Listing', $scope.store_listings);
                $scope.no_listings = false;
            };

            $scope.parse_store_listings = function(msg) {
                var contracts = msg.product;

                $scope.store_listings = [];
                $.each(contracts, function(key, value) {
                    console.log('value', value);
                    $scope.store_listings.push(value.contract_body);
                });

                //$scope.store_listings = jQuery.unique($scope.store_listings);
                $.each($scope.store_listings, function(index, contract) {
                    if (jQuery.isEmptyObject(contract.Contract.item_images)) {
                        contract.Contract.item_images = "img/no-photo.png";
                    }
                });


                $('#listing-loader').hide();
                console.log('New Listing', $scope.store_listings);

            };

            $scope.store_products = {};
            $scope.parse_store_products = function(msg) {

                console.log(msg);
                $scope.store_products = msg.products;
                // $scope.store_products.forEach(function(product) {
                //   console.log(product);
                //
                // })

            };
            $scope.parse_listing_results = function(msg) {
                $scope.store_products = msg.contracts;
            };

            function resetStorePanels() {
                $scope.storeInfoPanel = false;
                $scope.storeProductsPanel = false;
                $scope.storeReviewsPanel = false;
                $scope.storeOrderHistoryPanel = false;
                $scope.storeServicesPanel = false;
            }

            $scope.showStorePanel = function(panelName) {

                resetStorePanels();
                $scope.dashboard = false;

                switch (panelName) {
                    case 'storeInfo':
                        $scope.storeInfoPanel = true;
                        break;
                    case 'storeProducts':
                        $('#listing-loader').show();
                        $scope.store_listings = [];
                        $scope.subpanel = 'listings';
                        Connection.send('get_notaries', {});
                        break;
                    case 'storeOrders':
                        //$scope.storeOrdersPanel = true;
                        break;
                    case 'storeReviews':
                        $scope.storeReviewsPanel = true;
                        break;
                    case 'storeServices':
                        $scope.storeServicesPanel = true;
                        break;

                }

            };

            // Query for product listings from this store
            $scope.queryStoreProducts = function(storeID) {

                console.log('Querying for contracts in store: ' + storeID);
                $scope.storeProductsPanel = true;
                var query = {
                    'type': 'query_store_products',
                    'key': storeID
                };

                //setTimeout(function() {
                Connection.send('query_store_products', query);
                //}, 2000);

            };

            $scope.addNotary = function(guid, nickname) {

                $scope.page.isTrustedNotary = true;

                Connection.send('add_trusted_notary', { 'type': 'add_trusted_notary',
                    'guid': guid,
                    'nickname': nickname
                    }
                );

                Connection.send('refresh_settings', {});
                Notifier.success('Success', 'Notary added successfully.');


            };

            $scope.BuyItemCtrl = function($scope, $modal, $log) {

                $scope.open = function(size, myself, merchantPubkey, listing,
                    notaries, arbiters, btc_pubkey) {

                    // Send socket a request for order info
                    //Connection.send('query_order', { orderId: orderId } )
                    Connection.send('get_notaries', {});

                    notaries = [];
                    console.log('notaries', $scope.settings.notaries);
                    for(var i in $scope.settings.notaries) {
                        console.log('notary', $scope.settings.notaries[i]);
                        notary = $scope.settings.notaries[i];
                        if(notary.online) {
                            notaries.push(notary);
                        }
                    }

                    var modalInstance = $modal.open({
                        templateUrl: 'partials/modal/buyItem.html',
                        controller: $scope.BuyItemInstanceCtrl,
                        resolve: {
                            merchantPubkey: function() {
                                return merchantPubkey;
                            },
                            myself: function() {
                                return myself;
                            },
                            btc_pubkey: function() {
                                return btc_pubkey;
                            },
                            notaries: function() {
                                return notaries;
                            },
                            arbiters: function() {
                                return arbiters;
                            },
                            listing: function() {
                                return listing;
                            },
                            scope: function() {
                                return $scope;
                            }
                        },
                        size: size
                    });

                    modalInstance.result.then(function() {

                        $scope.showDashboardPanel('orders_purchases');

                        $('#pill-orders').addClass('active').siblings().removeClass('active').blur();
                        $("#orderSuccessAlert").alert();
                        window.setTimeout(function() {
                            $("#orderSuccessAlert").alert('close');
                        }, 5000);

                    }, function() {
                        $log.info('Modal dismissed at: ' + new Date());

                    });
                };
            };


            $scope.BuyItemInstanceCtrl = function($scope, $modalInstance, myself, merchantPubkey, listing,
                notaries,
                arbiters,
                btc_pubkey,
                scope) {

                console.log('Listing Info: ', listing);

                $scope.listing = listing;

                $scope.myself = myself;
                $scope.merchantPubkey = merchantPubkey;
                $scope.productTitle = listing.contract_body.Contract.item_title;
                $scope.productPrice = (listing.contract_body.Contract.item_price !== "") ? +listing.contract_body.Contract.item_price : 0;
                $scope.productDescription = listing.contract_body.Contract.item_desc;
                $scope.productImageData = listing.contract_body.Contract.item_images;
                $scope.productRemoteImages = listing.contract_body.Contract.item_remote_images;
                $scope.shippingPrice = (listing.contract_body.Contract.item_delivery.hasOwnProperty('shipping_price')) ? listing.contract_body.Contract.item_delivery.shipping_price : 0;
                $scope.totalPrice = +(parseFloat($scope.productPrice) + parseFloat($scope.shippingPrice)).toPrecision(8);
                $scope.productQuantity = 1;
                $scope.rawContract = listing.signed_contract_body;
                $scope.guid = listing.contract_body.Seller.seller_GUID;
                $scope.arbiters = arbiters;

                $scope.notaries = notaries;

                $scope.key = listing.key;

                $scope.update = function(user) {
                    console.log('Updated');
                };

                $scope.ok = function() {
                    $modalInstance.close();
                };

                $scope.cancel = function() {
                    $modalInstance.dismiss('cancel');
                };

                $scope.updateTotal = function() {
                    var newPrice = $('#itemQuantity').val() * $scope.productPrice;
                    newPrice = Math.round(newPrice * 100000) / 100000;
                    $('#totalPrice').html(+(parseFloat(newPrice) + parseFloat($scope.shippingPrice)).toPrecision(8));
                };

                $scope.gotoStep3 = function() {
                    $scope.order.step3 = 1;
                    $scope.order.step2 = '';
                };

                $scope.gotoStep2 = function() {
                    $scope.order.step2 = 1;
                    $scope.order.step3 = '';
                };

                $scope.gotoStep1 = function() {
                    $scope.order.step2 = '';
                };

                $scope.order = {
                    message: '',
                    tx: '',
                    listingKey: listing.key,
                    listingTotal: '',
                    productTotal: '',
                    productQuantity: 1,
                    rawContract: listing.signed_contract_body,
                    btc_pubkey: btc_pubkey
                };
                $scope.order.notary = ($scope.notaries.length > 0) ? $scope.notaries[0].guid : "";
                $scope.order.arbiter = $scope.arbiters[0];

                $scope.submitOrder = function() {

                    $scope.creatingOrder = false;
                    $scope.order.step3 = '';
                    $scope.order.step2 = '';
                    $scope.order.step1 = '';
                    $scope.order.confirmation = true;

                    var newOrder = {
                        'message': $scope.order.message,
                        'state': 'New',
                        'buyer': $scope.myself.pubkey,
                        'seller': $scope.merchantPubkey,
                        'sellerGUID': $scope.guid,
                        'listingKey': $scope.key,
                        'orderTotal': $('#totalPrice').html(),

                        'rawContract': $scope.rawContract,
                        'notary': $scope.order.notary,
                        'btc_pubkey': $scope.order.btc_pubkey,
                        'arbiter': $scope.order.arbiter,
                        'buyerRefundAddress': $scope.order.buyerRefundAddress
                    };
                    console.log(newOrder);
                    Connection.send('order', newOrder);
                    $scope.sentOrder = true;



                };

                $scope.closeConfirmation = function() {
                    $modalInstance.close();
                    window.location = '#/orders/purchases';
                };



            };

            if (Connection.websocket.readyState == 1) {
                $scope.load_page({});
            }


        }
    ]);
