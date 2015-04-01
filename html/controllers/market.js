/**
 * Market controller.
 *
 * @desc This controller is the main controller for the market.
 * It contains all of the single page application logic.
 * @param {!angular.Scope} $scope
 * @constructor
 */
angular.module('app')
    .controller('Market', ['$scope', '$route', '$interval', '$routeParams', '$location', 'Connection',
        function($scope, $route, $interval, $routeParams, $location, Connection) {

            $scope.newuser = true; // Should show welcome screen?
            $scope.page = false; // Market page has been loaded
            $scope.dashboard = true; // Show dashboard
            $scope.myInfoPanel = true; // Show information panel
            $scope.shouts = []; // Shout messages
            $scope.newShout = "";
            $scope.searching = "";
            $scope.currentReviews = [];
            $scope.myOrders = [];
            $scope.myReviews = [];

            $scope.peers = [];
            $scope.reviews = {};

            $scope.$emit('sidebar', true);

            /**
             * Establish message handlers
             * @msg - message from websocket to pass on to handler
             */
            $scope.$evalAsync( function( $scope ) {

                var listeners = Connection.$$listeners;
                if(!listeners.hasOwnProperty('order_notify')) {
                    Connection.$on('order_notify', function(e, msg){ $scope.order_notify(msg); });
                }
                if(!listeners.hasOwnProperty('republish_notify')) {
                    Connection.$on('republish_notify', function(e, msg){ $scope.republish_notify(msg); });
                }
                if(!listeners.hasOwnProperty('inbox_notify')) {
                    Connection.$on('inbox_notify', function(e, msg){ $scope.inbox_notify(msg); });
                }

                Connection.$on('peer', function(e, msg){ $scope.add_peer(msg); });
                Connection.$on('goodbye', function(e, msg){ $scope.goodbye(msg); });
                Connection.$on('hello_response', function(e, msg){ $scope.hello_response(msg); });
                Connection.$on('peers', function(e, msg){ $scope.update_peers(msg); });
                Connection.$on('peer_remove', function(e, msg){ $scope.remove_peer(msg); });
                if(!listeners.hasOwnProperty('inbox_count')) {
                    Connection.$on('inbox_count', function (e, msg) {
                        $scope.parse_inbox_count(msg);
                    });
                }
                Connection.$on('myself', function(e, msg){ $scope.parse_myself(msg); });
                Connection.$on('shout', function(e, msg){ $scope.parse_shout(msg); });
                Connection.$on('log_output', function(e, msg){ $scope.parse_log_output(msg); });
                Connection.$on('messages', function(e, msg){ $scope.parse_messages(msg); });
                Connection.$on('notaries', function(e, msg){ $scope.parse_notaries(msg); });
                Connection.$on('reputation', function(e, msg){ $scope.parse_reputation(msg); });
                Connection.$on('burn_info_available', function(e, msg){ $scope.parse_burn_info(msg); });

                Connection.$on('inbox_messages', function(e, msg){ $scope.parse_inbox_messages(msg); });
                Connection.$on('inbox_sent_messages', function(e, msg){ $scope.parse_inbox_sent_messages(msg); });

                Connection.$on('hello', function(e, msg){
                    console.log('Received a hello', msg);
                    $scope.add_peer({
                        'guid': msg.senderGUID,
                        'uri': msg.uri,
                        'pubkey': msg.pubkey,
                        'nick': msg.senderNick
                    });
                });
            });

            // Listen for Sidebar mods
            $scope.$on('sidebar', function(event, visible) {
                $scope.sidebar = visible;
            });

            var refresh_peers = function() {
                Connection.send('peers', {});
            };

            //$interval(refresh_peers,20000,0,true);

            /**
             * Create a shout and send it to all connected peers
             * Display it in the interface
             */
            $scope.createShout = function() {

                if($scope.newShout === '') {
                    return;
                }

                // launch a shout
                var newShout = {
                    'type': 'shout',
                    'text': $scope.newShout,
                    'pubkey': $scope.myself.pubkey,
                    'senderGUID': $scope.myself.guid,
                    'avatar_url': $scope.myself.settings.avatar_url ? $scope.myself.settings.avatar_url : ''
                };
                Connection.send('shout', newShout);
                $scope.shouts.push(newShout);
                $scope.newShout = '';
            };

            /**
             * Handles inbox count message from the server
             * @msg - Message from server
             */
            $scope.parse_inbox_count = function(msg) {
                console.log('Inbox count', msg);
                $scope.inbox_count = msg.count;
                if (!$scope.$$phase) {
                    $scope.$apply();
                }
            };

            // Toggle the sidebar hidden/shown
            $scope.toggleSidebar = function() {
                $scope.sidebar = !$scope.sidebar;
            };

            // Hide the sidebar
            $scope.hideSidebar = function() {
                $scope.sidebar = false;
            };

            // Show the sidebar
            $scope.showSidebar = function() {
                $scope.sidebar = true;
            };

            /**
             * [LEGACY] Adds review to a page
             * @pubkey -
             * @review -
             */
            var add_review_to_page = function(pubkey, review) {
                var found = false;

                console.log("Add review");

                if (!$scope.reviews.hasOwnProperty(pubkey)) {
                    $scope.reviews[pubkey] = [];
                }
                $scope.reviews[pubkey].forEach(function(_review) {
                    if (_review.sig == review.sig && _review.subject == review.subject && _review.pubkey == review.pubkey) {
                        console.log("Found a review for this market");
                        found = true;
                    }
                });
                if (!found) {
                    // check if the review is about me
                    if ($scope.myself.pubkey == review.subject) {
                        console.log("Found review for myself");
                        $scope.myReviews.push(review);
                    }
                    $scope.reviews[pubkey].push(review);
                }
            };



            /**
             * Send log line to GUI
             * @msg - Message from server
             */
            $scope.parse_log_output = function(msg) {
                console.log(msg);
                $scope.log_output += msg.line;

            };

            /**
             * Load notaries array into the GUI
             * @msg - Message from server
             */
            $scope.parse_notaries = function(msg) {
                $scope.trusted_notaries = msg.notaries;
            };

            $scope.parse_welcome = function(msg) {

                console.log(msg);

            };

            $scope.guid_to_avatar = function(guid) {

            };

            $scope.getNumber = function(num) {
                return new Array(num);
            };

            $scope.orders_page_changed = function() {
                console.log(this.orders_current_page);
                var query = {
                    'page': this.orders_current_page - 1,
                    'merchant': $scope.merchant
                };
                Connection.send('query_orders', query);

            };

            $scope.parse_contracts = function(msg) {

                console.log(msg);

                var page = msg.page;

                $scope.contracts = msg.contracts.contracts;

                $scope.total_contracts = msg.contracts.total_contracts;
                $scope.contracts_pages = $scope.total_contracts % 10;
                console.log('contracts', $scope.total_contracts);
                $scope.contracts_current_page = (page > 0) ? page - 1 : 0;
                console.log($scope);

                for (var key in msg.contracts.contracts) {

                    var obj = msg.contracts.contracts[key];
                    for (var prop in obj) {
                        if (prop == 'item_images' && jQuery.isEmptyObject(msg.contracts.contracts[key].item_images)) {
                            msg.contracts.contracts[key].item_images = "img/no-photo.png";
                        }

                    }

                }

                $scope.contract2 = {};

            };

            $scope.message = {};
            $scope.parse_messages = function(msg) {
                if (msg !== null &&
                    msg.messages !== null &&
                    msg.messages.messages !== null &&
                    msg.messages.messages.inboxMessages !== null) {

                    $scope.messages = msg.messages.messages.inboxMessages;

                    $scope.message = {};
                }
            };

            $scope.inbox_messages = {};
            $scope.inbox_sent_messages = {};

            $scope.parse_inbox_messages = function(msg) {
                console.log(msg);
                $scope.inbox_messages = msg.messages;
            };

            $scope.parse_inbox_sent_messages = function(msg) {
                console.log(msg);
                $scope.inbox_sent_messages = msg.messages;
            };

            $scope.parse_burn_info = function(msg) {
                // console.log('Burn info available!');
                var SATOSHIS_IN_BITCOIN = 100000000;
                var amountInSatoshis = msg.amount;
                var bitcoins = msg.amount / SATOSHIS_IN_BITCOIN;
                bitcoins = Math.round(bitcoins * 10000) / 10000;

                // console.log(bitcoins);
                console.log('Trust Pledge:', bitcoins+'BTC', msg.addr);
                $scope.settings.burnAmount = bitcoins;
                $scope.settings.burnAddr = msg.addr;
            };

            // Peer information has arrived
            $scope.parse_reputation = function(msg) {

                console.log('Parsing reputation', msg.reviews);
                msg.reviews.forEach(function(review) {
                    add_review_to_page(review.subject, review);
                });
            };

            // Check if peer is already known by comparing the public key
            $scope.add_peer = function(msg) {
                var alreadyExists = false;
                angular.forEach($scope.peers,function(peer,index){
                    if(peer.pubkey === msg.pubkey){
                        alreadyExists = true;
                    }
                });

                if(!alreadyExists){
                    $scope.peers.push(msg);
                }
            };


            $scope.goodbye = function(msg) {

                console.log('Goodbye');
                /* get index if peer is already known */
                var index = [-1].concat($scope.myself.peers).reduce(
                    function(previousValue, currentValue, index, array) {
                        return currentValue.guid == msg.senderGUID ? index : previousValue;
                    });

                if (index >= 0) {
                    /* it is a new peer */
                    console.log('Removing peer');
                    $scope.myself.peers.splice(index, 1);
                    $scope.peers = $scope.myself.peers;
                }
            };

            $scope.hello_response = function(msg) {
                console.log('Hello Response', msg);
                refresh_peers();
            };

            $scope.update_peers = function(msg) {
                console.log('Refresh peers: ', msg);
                $scope.peers = msg.peers;
            };

            $scope.remove_peer = function(msg) {

                console.log('Remove peer: ', msg);

                $scope.peers = $scope.peers.filter(function(element) {
                    return element.uri != msg.uri;
                });
            };

            $scope.review = {
                rating: 5,
                text: ""
            };
            $scope.addReview = function() {

                var query = {
                    'type': 'review',
                    'pubkey': $scope.page.pubkey,
                    'text': $scope.review.text,
                    'rating': parseInt($scope.review.rating)
                };
                Connection.send('review', query);

                // store in appropriate format (its different than push format :P)
                add_review_to_page($scope.page.pubkey, {
                    type: 'review',
                    'pubkey': $scope.myself.pubkey,
                    'subject': $scope.page.pubkey,
                    'rating': query.rating,
                    text: query.text
                });

                $scope.review.rating = 5;
                $scope.review.text = '';
                $scope.showReviewForm = false;
            };

            // My information has arrived
            $scope.parse_myself = function(msg) {
                $scope.myself = msg;

                // Settings
                $scope.settings = msg.settings;

                //msg.reputation.forEach(function(review) {
                //   add_review_to_page($scope.myself.pubkey, review)
                //});

                msg.peers.forEach(function(peer) {
                    if(peer.guid !== '') {
                        $scope.add_peer(peer);
                    }
                });

            };

            // A shout has arrived
            $scope.parse_shout = function(msg) {
                $scope.shouts.push(msg);
                console.log('Shout', $scope.shouts);
            };

            $scope.checkOrderCount = function() {
                Connection.send('check_order_count', {});
            };

            $scope.settings = {
                email: '',
                PGPPubKey: '',
                bitmessage: '',
                pubkey: '',
                secret: '',
                nickname: '',
                welcome: '',
                trustedArbiters: {},
                trustedNotaries: {}
            };

            $scope.order_notify = function(msg) {
                console.log(msg);
                Notifier.info('Order Update', msg.msg);
            };
            $scope.republish_notify = function(msg) {
                Notifier.info('Network Update', msg.msg);
            };
            $scope.inbox_notify = function(msg) {
                console.log(msg);
                Notifier.info('"' + msg.msg.subject + '"', 'Message from ' + msg.msg.senderNick);
            };

            // Create a new order and send to the network
            $scope.newOrder = {
                message: '',
                tx: '',
                listingKey: '',
                productTotal: ''
            };

            $scope.createOrder = function() {

                $scope.creatingOrder = false;

                var newOrder = {
                    'text': $scope.newOrder.message,
                    'state': 'New',
                    'buyer': $scope.myself.pubkey,
                    'seller': $scope.page.pubkey,
                    'listingKey': $scope.newOrder.pubkey
                };

                Connection.send('order', newOrder);
                $scope.sentOrder = true;

                $scope.showDashboardPanel('orders');

                $('#pill-orders').addClass('active').siblings().removeClass('active').blur();
                $("#orderSuccessAlert").alert();
                window.setTimeout(function() {
                    $("#orderSuccessAlert").alert('close');
                }, 5000);

            };
            $scope.payOrder = function(order) {
                order.state = 'Paid';
                order.tx = $scope.newOrder.tx;
                $scope.newOrder.tx = '';
                Connection.send('order', order);
            };
            $scope.receiveOrder = function(order) {
                order.state = 'Received';
                Connection.send('order', order);
            };
            $scope.sendOrder = function(order) {
                order.state = 'Sent';
                Connection.send('order', order);

                $scope.queryMyOrder(0);

            };

            $scope.cancelOrder = function(order) {
                order.state = 'cancelled';
                Connection.send('order', order);
            };

            $scope.addArbiter = function(arbiter) {
                var arbiterGUID = (arbiter !== '') ? arbiter : $('#inputArbiterGUID').val();
                $('#inputArbiterGUID').val('');

                // TODO: Check for valid arbiter GUID
                //if(arbiterGUID.length != 38 || !arbiterGUID.match(/^[0-9a-zA-Z]+$/)) {
                //    alert('Incorrect format for GUID');
                //    return;
                //}

                if (!$scope.settings.trustedArbiters) {
                    $scope.settings.trustedArbiters = [];
                }
                $scope.settings.trustedArbiters.push(arbiterGUID);

                // Dedupe arbiter GUIDs
                var uniqueArbiters = [];
                $.each($scope.settings.trustedArbiters, function(i, el) {
                    if ($.inArray(el, uniqueArbiters) === -1) {
                        uniqueArbiters.push(el);
                    }
                });

                $scope.settings.trustedArbiters = uniqueArbiters;

                $scope.saveSettings(false);
                Notifier.success('Success', 'Arbiter added successfully.');
            };

            $scope.removeArbiter = function(arbiterGUID) {

                // Dedupe arbiter GUIDs
                var uniqueArbiters = $scope.settings.trustedArbiters;
                $.each($scope.settings.trustedArbiters, function(i, el) {
                    if (el == arbiterGUID) {
                        uniqueArbiters.splice(i, 1);
                    }
                });

                $scope.settings.trustedArbiters = uniqueArbiters;

                $scope.saveSettings(false);
                Notifier.success('Success', 'Arbiter removed successfully.');
            };

            $scope.compose_message = function(size, myself, address, subject) {
                $scope.$broadcast("compose_message", {
                    size: size,
                    myself: myself,
                    bm_address: address,
                    subject: subject
                });
            };

            $scope.clearDHTData = function() {
                Connection.send('clear_dht_data', {});
                Notifier.success('Success', 'DHT cache cleared');
            };

            $scope.clearPeers = function() {
                Connection.send('clear_peers_data', {});
                Notifier.success('Success', 'Peers table cleared');
            };



            function resetPanels() {
                $scope.messagesPanel = false;
                $scope.reviewsPanel = false;
                $scope.productCatalogPanel = false;
                $scope.settingsPanel = false;
                $scope.arbitrationPanel = false;
                $scope.ordersPanel = false;
                $scope.myInfoPanel = false;
                $scope.searchPanel = false;
            }

            $scope.showDashboardPanel = function(panelName, e) {
                if (e) {
                    e.preventDefault();
                }

                resetPanels();

                if (panelName != 'myInfo') {
                    $scope.hideSidebar();
                    $('#dashboard-container').removeClass('col-sm-8').addClass('col-sm-12');
                } else {
                    $scope.showSidebar();
                    $('#dashboard-container').removeClass('col-sm-12').addClass('col-sm-8');
                }

                $scope.dashboard = true;
                $scope.page = false;

                switch (panelName) {
                    case 'messages':
                        $scope.queryMessages();
                        $scope.messagesPanel = true;
                        break;
                    case 'reviews':
                        $scope.reviewsPanel = true;
                        break;

                    case 'arbitration':
                        $scope.arbitrationPanel = true;
                        break;


                    case 'myInfo':
                        $scope.myInfoPanel = true;
                        break;

                }

            };

            $scope.getNotaries = function() {
                Connection.send('get_notaries', {});
            };

            $scope.goToStore = function(url, guid) {
                $scope.awaitingStore = guid;
                $scope.page = null;
                $scope.go(url);
            };

            $scope.go = function (url) {
              $location.path(url);
            };

            /**
             * Query the network for a merchant and then
             * show the page
             * @guid - GUID of page to load
             */
            $scope.queryShop = function(guid) {

                $scope.awaitingShop = guid;
                console.log('Querying for shop [market]: ', guid);

                var query = {
                    'type': 'query_page',
                    'findGUID': guid
                };

                $scope.page = null;
                Connection.send('query_page', query);

            };

            $scope.queryMessages = function() {
                // Query for messages
                var query = {
                    'type': 'query_messages'
                };
                console.log('querying messages');
                Connection.send('query_messages', query);
                console.log($scope.myself.messages);

            };

            // Modal Code
            $scope.WelcomeModalCtrl = function($scope, $modal, $log, $rootScope) {

                // Listen for changes to settings and if welcome is empty then show the welcome modal
                $scope.$watch('settings', function() {
                    console.log('settings', $scope.settings);
                    if ($scope.settings.welcome == "enable") {
                        $scope.open('lg', 'static');
                    } else {
                        return;
                    }

                    /*Else process your data*/
                });

                $scope.open = function(size, backdrop, scope) {

                    backdrop = backdrop ? backdrop : true;

                    var modalInstance = $modal.open({
                        templateUrl: 'partials/welcome.html',
                        controller: ModalInstanceCtrl,
                        size: size,
                        backdrop: backdrop,
                        resolve: {
                            settings: function() {
                                return $scope.settings;
                            }
                        }
                    });

                    modalInstance.result.then(function(selectedItem) {
                        $scope.selected = selectedItem;
                    }, function() {
                        $log.info('Modal dismissed at: ' + new Date());
                    });

                };

            };

            // Please note that $modalInstance represents a modal window (instance) dependency.
            // It is not the same as the $modal service used above.

            var ModalInstanceCtrl = function($scope, $modalInstance, settings) {

                $scope.settings = settings;
                // $scope.selected = {
                //   item: $scope.items[0]
                // };
                //

                $scope.welcome = settings.welcome;

                $scope.ok = function() {
                    Connection.send('welcome_dismissed', {});
                    $modalInstance.dismiss('cancel');
                };

                $scope.cancel = function() {
                    $modalInstance.dismiss('cancel');
                };
            };

            $scope.ComposeMessageCtrl = function($scope, $modal, $log) {

                $scope.$on("compose_message", function(event, args) {
                    $scope.bm_address = args.bm_address;
                    $scope.size = args.size;
                    $scope.subject = args.subject;
                    $scope.myself = args.myself;

                    $scope.compose($scope.size, $scope.myself, $scope.bm_address, $scope.subject);
                });


                $scope.compose = function(size, myself, to_address, msg) {
                    var composeModal = $modal.open({
                        templateUrl: 'partials/modal/composeMessage.html',
                        controller: $scope.ComposeMessageInstanceCtrl,
                        resolve: {
                            myself: function() {
                                return myself;
                            },
                            to_address: function() {
                                return to_address;
                            },
                            msg: function() {
                                return msg;
                            },
                        },
                        size: size
                    });
                    var afterFunc = function() {
                        $scope.showDashboardPanel('messages');
                    };
                    composeModal.result.then(
                        afterFunc,
                        function() {
                            $scope.queryMessages();
                            $log.info('Modal dismissed at: ' + new Date());
                        }
                    );
                };

                $scope.view = function(size, myself, to_address, msg) {
                    var viewModal = $modal.open({
                        templateUrl: 'partials/modal/viewMessage.html',
                        controller: $scope.ViewMessageInstanceCtrl,
                        resolve: {
                            myself: function() {
                                return myself;
                            },
                            to_address: function() {
                                return to_address;
                            },
                            msg: function() {
                                return msg;
                            }
                        },
                        size: size
                    });
                    var afterFunc = function() {
                        $scope.showDashboardPanel('messages');
                    };
                    viewModal.result.then(
                        afterFunc,
                        function() {
                            $log.info('Modal dismissed at: ' + new Date());
                        }
                    );
                };
            };

            $scope.ViewMessageInstanceCtrl = function($scope, $modalInstance, myself, to_address, msg) {
                $scope.myself = myself;
                $scope.my_address = myself.bitmessage;
                $scope.to_address = to_address;
                $scope.msg = msg;

                // Fill in form if msg is passed - reply mode
                if (msg !== null) {
                    $scope.toAddress = msg.fromAddress;
                    // Make sure subject start with RE:
                    var sj = msg.subject;
                    if (sj.match(/^RE:/) === null) {
                        sj = "RE: " + sj;
                    }
                    $scope.subject = sj;
                    // Quote message
                    var quote_re = /^(.*?)/mg;
                    var quote_msg = msg.message.replace(quote_re, "> $1");
                    $scope.body = "\n" + quote_msg;
                }

                $scope.send = function() {
                    // Trigger validation flag.
                    $scope.submitted = true;

                    // If form is invalid, return and let AngularJS show validation errors.
                    if (composeForm.$invalid) {
                        return;
                    }

                    var query = {
                        'type': 'send_message',
                        'to': toAddress.value,
                        'subject': subject.value,
                        'body': body.value
                    };
                    console.log('sending message with subject ' + subject);
                    Connection.send('send_message', query);

                    $modalInstance.close();
                };

                $scope.close = function() {
                    $modalInstance.dismiss('cancel');
                };
            };

            $scope.ComposeMessageInstanceCtrl = function($scope, $modalInstance, myself, to_address, msg) {

                $scope.myself = myself;
                $scope.to_address = to_address;
                $scope.msg = msg;

                // Fill in form if msg is passed - reply mode
                if (msg !== null) {
                    $scope.toAddress = msg.fromAddress;
                    // Make sure subject start with RE:
                    var sj = msg.subject;
                    if (sj.match(/^RE:/) === null) {
                        sj = "RE: " + sj;
                    }
                    $scope.subject = sj;
                    // Quote message
                    var quote_re = /^(.*?)/mg;
                    var quote_msg = msg.message.replace(quote_re, "> $1");
                    $scope.body = "\n" + quote_msg;
                }

                $scope.send = function() {
                    // Trigger validation flag.
                    $scope.submitted = true;

                    // If form is invalid, return and let AngularJS show validation errors.
                    if (composeForm.$invalid) {
                        return;
                    }

                    var query = {
                        'type': 'send_message',
                        'to': toAddress.value,
                        'subject': subject.value,
                        'body': body.value
                    };
                    Connection.send('send_message', query);

                    $modalInstance.close();
                };

                $scope.cancel = function() {
                    $modalInstance.dismiss('cancel');
                };


            };

            $scope.NewMessageCtrl = function($scope, $modal, $log) {

                $scope.$on("compose_inbox_message", function(event, args) {
                    console.log('compose_inbox_message');

                    $scope.guid = args.guid;
                    $scope.size = args.size;
                    $scope.subject = args.subject;
                    $scope.myself = args.myself;

                    $scope.compose($scope.size, $scope.myself, $scope.guid, $scope.subject);
                });

                $scope.guid_to_nickname = function(guid) {
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

                $scope.compose = function(size, myself, recipient, msg) {

                    var composeModal = $modal.open({
                        templateUrl: 'partials/modal/newMessage.html',
                        controller: $scope.NewMessageInstanceCtrl,
                        resolve: {
                            myself: function() {
                                return myself;
                            },
                            recipient: function() {
                                return recipient;
                            },
                            msg: function() {
                                return msg;
                            },
                            scope: function() {
                                return $scope;
                            }
                        },
                        size: size
                    });
                    var afterFunc = function() {
                        return;
                    };
                    composeModal.result.then(
                        afterFunc,
                        function() {
                            $log.info('Modal dismissed at: ' + new Date());
                        }
                    );
                };

                $scope.view = function(size, myself, msg) {
                    var viewModal = $modal.open({
                        templateUrl: 'partials/modal/viewInboxMessage.html',
                        controller: ViewInboxMessageInstanceCtrl,
                        resolve: {
                            myself: function() {
                                return myself;
                            },
                            msg: function() {
                                return msg;
                            },
                            scope: function() {
                                return $scope;
                            }
                        },
                        size: size
                    });
                    var afterFunc = function() {
                        $scope.showDashboardPanel('inbox');
                    };
                    viewModal.result.then(
                        afterFunc,
                        function() {
                            $log.info('Modal dismissed at: ' + new Date());
                        }
                    );
                };
            };

            $scope.NewMessageInstanceCtrl = function($scope, $modalInstance, myself, recipient, msg, scope) {

                function guid_to_peer(guid) {
                    for(var peer in $scope.myself.peers) {
                        peer = $scope.myself.peers[peer];
                        if(peer.guid == guid) {
                            return peer;
                        }
                    }
                    return {};
                }

                $scope.myself = myself;
                $scope.recipient = (recipient !== '') ? guid_to_peer(recipient) : '';
                $scope.msg = msg;

                // Fill in form if msg is passed - reply mode
                if (msg !== null) {
                    $scope.recipient = msg.recipient;

                    // Make sure subject start with RE:
                    var sj = msg.subject;
                    if (sj.match(/^RE:/) === null) {
                        sj = "RE: " + sj;
                    }
                    $scope.subject = sj;

                    // Quote message
                    var quote_re = /^(.*?)/mg;
                    var quote_msg = msg.message.replace(quote_re, "> $1");
                    $scope.body = "\n" + quote_msg;
                }

                $scope.send = function() {
                    // Trigger validation flag.
                    $scope.submitted = true;

                    // If form is invalid, return and let AngularJS show validation errors.
                    if (sendMessageForm.$invalid) {
                        return;
                    }

                    var query = {
                        'type': 'send_inbox_message',
                        'recipient': this.recipient.guid,
                        'subject': subject.value,
                        'body': body.value
                    };

                    Connection.send('send_inbox_message', query);
                    $modalInstance.close();
                };

                $scope.cancel = function() {
                    $modalInstance.dismiss('cancel');
                };


            };

            var ViewInboxMessageInstanceCtrl = function($scope, $modalInstance, myself, msg, scope) {
                $scope.myself = myself;
                $scope.inbox = {};
                $scope.inbox.message = msg;

                $scope.inbox.message.nickname = scope.guid_to_nickname(msg.sender_guid);

                console.log('test', $scope);

                // Fill in form if msg is passed - reply mode
                if (msg !== null) {

                    // Make sure subject start with RE:
                    var sj = msg.subject;
                    if (sj.match(/^RE:/) === null) {
                        sj = "RE: " + sj;
                    }
                    $scope.subject = sj;
                    // Quote message
                    var quote_re = /^(.*?)/mg;

                    //var quote_msg = $scope.msg.body.replace(quote_re, "> $1");
                    //$scope.body = "\n" + quote_msg;
                }

                $scope.send = function() {
                    // Trigger validation flag.
                    $scope.submitted = true;

                    // If form is invalid, return and let AngularJS show validation errors.
                    if (composeForm.$invalid) {
                        return;
                    }

                    var query = {
                        'type': 'send_message',
                        'to': toAddress.value,
                        'subject': subject.value,
                        'body': body.value
                    };
                    console.log('sending message with subject ' + subject);
                    Connection.send('send_message', query);

                    $modalInstance.close();
                };

                $scope.close = function() {
                    $modalInstance.dismiss('cancel');
                };
            };

            // Modal Code
            $scope.AddNodeModalCtrl = function($scope, $modal, $log) {

                $scope.open = function(size, backdrop, scope) {

                    backdrop = backdrop ? backdrop : true;

                    var modalInstance = $modal.open({
                        templateUrl: 'partials/modal/addNode.html',
                        controller: AddNodeModalInstance,
                        size: size,
                        backdrop: backdrop,
                        resolve: {}
                    });

                    modalInstance.result.then(function(selectedItem) {
                        $scope.selected = selectedItem;
                    }, function() {
                        $log.info('Modal dismissed at: ' + new Date());
                    });

                };

            };

            var AddNodeModalInstance = function($scope, $modalInstance) {

                $scope.addGUID = function(newGUID) {

                    if (newGUID.length == 40 && newGUID.match(/^[A-Za-z0-9]+$/)) {
                        Connection.send('add_node', {
                            'type': 'add_guid',
                            'guid': newGUID
                        });
                        console.log('Added node by GUID');
                        Notifier.success('Success', 'GUID is valid');
                    } else {
                        Notifier.info('Failure', 'GUID is not valid');
                    }
                    $modalInstance.dismiss('cancel');
                };

                $scope.cancel = function() {
                    $modalInstance.dismiss('cancel');
                };
            };

        }
    ]);
