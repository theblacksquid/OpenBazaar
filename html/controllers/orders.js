/**
 * Orders controller.
 *
 * @desc This controller is the orders controller.
 * @param {!angular.Scope} $scope
 * @constructor
 */
angular.module('app')
    .controller('Orders', ['$scope', '$interval', '$routeParams', '$location', 'Connection', '$rootScope',
        function($scope, $interval, $routeParams, $location, Connection, $rootScope) {

            $scope.myOrders = [];
            $scope.ordersPanel = true;
            $scope.path = $location.path();
            $scope.$emit('sidebar', false);

            /**
             * Establish message handlers
             * @msg - message from websocket to pass on to handler
             */
            Connection.$on('load_page', function(e, msg){ $scope.load_page(msg); });
            Connection.$on('order', function(e, msg){ $scope.parse_order(msg); });
            Connection.$on('order_count', function(e, msg){ $scope.parse_order_count(msg); });
            Connection.$on('myorders', function(e, msg){ $scope.parse_myorders(msg); });
            Connection.$on('orderinfo', function(e, msg){ $scope.parse_orderinfo(msg); });
            Connection.$on('order_payment_amount', function(e, msg){ $scope.parse_payment_amount(msg); });

            var guid_to_nickname = function(guid) {
                if(guid == $scope.myself.guid) {
                    return $scope.myself.settings.nickname;
                }

                for(var peer in $scope.myself.peers) {
                    peer = $scope.myself.peers[peer];
                    if(peer.guid == guid) {
                        return peer.nick;
                    }
                }

                return '';
            };
            $scope.guid_to_nickname = guid_to_nickname;

            $scope.load_page = function(msg) {
                console.log($scope.path);
                if($scope.path === "/orders/sales") {
                    $scope.queryMyOrder(1);
                } else if($scope.path === "/orders/notarizations") {
                    $scope.queryMyOrder(2);
                } else {
                    $scope.queryMyOrder(0);

                }
            };

            $scope.parse_myorders = function(msg) {

                $scope.orders = msg.orders;
                $scope.orders_total = msg.total;
                $scope.orders_pages = msg.total % 10;
                $scope.orders_current_page = msg.page + 1;

            };

            $scope.queryMyOrder = function(merchant) {
                // Query for orders
                var query = {
                    'type': 'query_orders',
                    'merchant': merchant
                };
                $scope.merchant = merchant;
                Connection.send('query_orders', query);
                if (!$scope.$$phase) {
                    $scope.$apply();
                }
            };

            /**
             * Parse order message from server for modal
             * @msg - Message from server
             */
            $scope.parse_order = function(msg) {

                $scope.myOrders = [];
                if ($scope.myOrders.hasOwnProperty(msg.id)) {
                    console.log("Updating order!");
                    $scope.myOrders[msg.id].state = msg.state;
                    $scope.myOrders[msg.id].tx = msg.tx;
                    $scope.myOrders[msg.id].notary = msg.notary;
                    $scope.myOrders[msg.id].item_price = msg.item_price;
                    $scope.myOrders[msg.id].shipping_price = msg.shipping_price;
                    $scope.myOrders[msg.id].item_quantity = msg.item_quantity;
                    //$scope.myOrders[msg.id].total_price = parseFloat(msg.item_price) + parseFloat(msg.shipping_price)
                    $scope.myOrders[msg.id].address = msg.address;
                    $scope.myOrders[msg.id].buyer = msg.buyer;
                    $scope.myOrders[msg.id].merchant = msg.merchant;
                    $scope.myOrders[msg.id].shipping_address = msg.shipping_address;
                    $scope.myOrders[msg.id].note_for_merchant = msg.note_for_merchant;
                    return;
                } else {
                    $scope.myOrders.push(msg);
                }
                if (!$scope.$$phase) {
                    console.log('My Orders', $scope.myOrders);
                    $scope.$apply();
                }
            };

            $scope.compose_message = function(size, myself, address, subject) {
                $rootScope.$broadcast("compose_message", {
                    size: size,
                    myself: myself,
                    bm_address: address,
                    subject: subject
                });
            };

            /**
             * Parse order message from server for modal
             * @msg - Message from server
             */
            $scope.parse_orderinfo = function(msg) {

                console.log("Order info retrieved");
                console.log(msg.order);

                $scope.modalOrder = msg.order;
                $scope.modalOrder.refundRecipientId = 1;
                console.log(msg.order);

                if (msg.order.state == 'Accepted' || msg.order.state == 'Waiting for Payment') {
                    $scope.modalOrder.waitingForPayment = true;
                } else if (msg.order.state == 'Paid' || msg.order.state == 'Buyer Paid') {
                    console.log('order', msg.order, $scope.myself.guid);
                    if (msg.order.merchant == $scope.myself.guid) {
                        $scope.modalOrder.waitingForShipment = true;
                    } else {
                        $scope.modalOrder.waitingForSellerToShip = true;
                    }
                } else if (msg.order.state == 'Sent') {
                    $scope.modalOrder.flagForArbitration = true;
                } else {
                    $scope.modalOrder.waitingForPayment = false;
                }

                $scope.modalOrder.item_quantity = msg.order.item_quantity;

                if (msg.order.state == 'Notarized') {
                    $scope.modalOrder.notary = $scope.myself.guid;
                }

                if(typeof $scope.modalOrder.shipping_address === "string" && $scope.modalOrder.shipping_address !== "") {
                    $scope.modalOrder.shipping_address = JSON.parse($scope.modalOrder.shipping_address);
                }

                if (!$scope.$$phase) {
                    $scope.$apply();
                }
            };

            $scope.parse_payment_amount = function(msg) {
                console.log(msg.value);
                $scope.order_balances = {};
                $scope.order_balances[msg.order_id] = msg.value;

                if(msg.value && $scope.modalOrder) {
                    $scope.modalOrder.payment_amount = parseInt(msg.value)/100000000;
                }
            };

            /**
             * Handles orders count message from the server
             * @msg - Message from server
             */
            $scope.parse_order_count = function(msg) {
                console.log(msg);
                $scope.orders_new = msg.count;
                if (!$scope.$$phase) {
                    $scope.$apply();
                }
            };

            $scope.ViewOrderCtrl = function($scope, $modal, $log) {

                $scope.open = function(size, orderId, settings, order) {

                    // Send socket a request for order info
                    Connection.send('query_order', {
                        orderId: orderId
                    });

                    var modalInstance = $modal.open({
                        templateUrl: 'partials/modal/viewOrder.html',
                        controller: ViewOrderInstanceCtrl,
                        size: size,
                        resolve: {
                            orderId: function() {
                                return orderId;
                            },
                            order: function() {
                                return order;
                            },
                            settings: function() {
                                return settings;
                            },
                            scope: function() {
                                return $scope;
                            }
                        }
                    });

                    modalInstance.result.then(function() {

                    }, function() {
                        $log.info('Modal dismissed at: ' + new Date());
                    });
                };

            };


            var ViewOrderInstanceCtrl = function($scope, $modalInstance, orderId, scope, settings, order) {

                $scope.orderId = orderId;
                $scope.order = order;
                $scope.Market = scope;
                $scope.settings = settings;
                $scope.orders_current_page = 0;

                $scope.markOrderPaid = function(orderId) {

                    Connection.send("pay_order", {
                        orderId: orderId
                    });

                    scope.modalOrder.state = 'Paid';

                    // Refresh orders in background
                    scope.queryMyOrder(0);

                    if (!$scope.$$phase) {
                        $scope.$apply();
                    }

                };

                $scope.refundRecipient = function() {
                    console.log($scope.Market.modalOrder.refundRecipientId);
                    Connection.send("refund_recipient", {
                        recipientId: $scope.Market.modalOrder.refundRecipientId,
                        orderId: orderId
                    });
                };

                $scope.guid_to_nickname = guid_to_nickname;

                $scope.compose_inbox_message = function(size, myself, guid, subject) {
                    console.log('Composing Inbox Message');
                    $rootScope.$broadcast("compose_inbox_message", {
                        size: size,
                        myself: myself,
                        guid: guid,
                        subject: subject
                    });
                };

                $scope.markOrderShipped = function(orderId) {

                    Connection.send("ship_order", {
                        orderId: orderId,
                        paymentAddress: scope.modalOrder.paymentAddress
                    });

                    scope.modalOrder.state = 'Shipped';
                    scope.modalOrder.waitingForShipment = false;
                    scope.queryMyOrder(1);

                    if (!$scope.$$phase) {
                        $scope.$apply();
                    }

                };

                $scope.markOrderReceived = function(orderId) {

                    Connection.send("release_payment", {
                        orderId: orderId
                    });

                    scope.modalOrder.state = 'Completed';
                    scope.queryMyOrder(0);

                    if (!$scope.$$phase) {
                        $scope.$apply();
                    }

                };

                $scope.ok = function() {
                    $modalInstance.close();
                };

                $scope.cancel = function() {
                    $modalInstance.dismiss('cancel');
                };
            };

            if (Connection.websocket.readyState == 1) {
                $scope.load_page({});
            }

        }
    ]);
