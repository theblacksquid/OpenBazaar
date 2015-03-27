/**
 * Inbox controller.
 *
 * @desc This controller is the inbox controller.
 * @param {!angular.Scope} $scope
 * @constructor
 */
angular.module('app')
    .controller('Inbox', ['$scope', '$interval', '$routeParams', '$location', 'Connection',
        function($scope, $interval, $routeParams, $location, Connection) {

            $scope.path = $location.path();
            $scope.$emit('sidebar', false);

            /**
             * Establish message handlers
             * @msg - message from websocket to pass on to handler
             */
            Connection.$on('load_page', function(e, msg){ $scope.load_page(msg); });
            Connection.$on('inbox', function(e, msg){ $scope.parse_messages(msg); });

            $scope.getInboxMessages = function() {
                var query = {
                    'type': 'get_inbox_messages'
                };
                console.log('Getting inbox messages');
                Connection.send('get_inbox_messages', query);
                Connection.send('get_inbox_sent_messages', query);
                console.log($scope.inbox_messages);
            };

            $scope.getInboxSentMessages = function() {
                var query = {
                    'type': 'get_inbox_sent_messages'
                };
                console.log('Getting inbox sent messages');
                Connection.send('get_inbox_sent_messages', query);
                console.log($scope.inbox_sent_messages);
            };

            $scope.load_page = function(msg) {
                $scope.inboxPanel = true;
                $scope.getInboxMessages();
            };

            if (Connection.websocket.readyState == 1) {
                $scope.load_page({});
            }

            $scope.message = {};
            $scope.parse_messages = function(msg) {
                console.log('parsing messages',msg);
                if (msg !== null &&
                    msg.messages !== null &&
                    msg.messages.messages !== null &&
                    msg.messages.messages.inboxMessages !== null) {

                    $scope.messages = msg.messages.messages.inboxMessages;

                    $scope.message = {};
                    if (!$scope.$$phase) {
                        $scope.$apply();
                    }
                }
            };


        }
    ]);
