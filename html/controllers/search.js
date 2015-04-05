/**
 * Search controller.
 *
 * @desc This controller is the search controller.
 * @param {!angular.Scope} $scope
 * @constructor
 */
angular.module('app')
    .controller('Search', ['$scope', '$interval', '$routeParams', '$location', 'Connection',
        function($scope, $interval, $routeParams, $location, Connection) {

            $scope.searchPanel = true;
            $scope.path = $location.path();
            $scope.$emit('sidebar', false);

            /**
             * Establish message handlers
             * @msg - message from websocket to pass on to handler
             */

            var listeners = Connection.$$listeners;

            listeners.load_page = [];
            Connection.$on('load_page', function(e, msg){ $scope.load_page(msg); });
            Connection.$on('global_search_result', function(e, msg){ $scope.parse_search_result(msg); });
            listeners.query_listing_result = [];
            Connection.$on('query_listing_result', function(e, msg){ $scope.parse_query_listing_result(msg); });


            $scope.load_page = function(msg) {
                console.log($location.search());
                $('#dashboard-container').removeClass('col-sm-8').addClass('col-sm-12');
                $scope.searchNetwork();
            };

            function getJsonFromUrl() {
                var query = location.search.substr(1);
                var result = {};
                query.split("&").forEach(function(part) {
                    var item = part.split("=");
                    result[item[0]] = decodeURIComponent(item[1]);
                });
                return result;
            }

            var url_json = getJsonFromUrl();
            $scope.search = url_json.searchterm;

            $scope.search = $scope.search.replace("+", " ");
            console.log('Search term: ', $scope.search);

            $scope.searchNetwork = function() {

                var query = {
                    'type': 'search',
                    'key': $scope.search
                };
                $scope.searching = $scope.search;

                $scope.search_results = {};
                $scope.awaitingQuery = $scope.search;
                Connection.send('search', query);
                $scope.search = "";
                $scope.showDashboardPanel('search');

            };

            $scope.isEmpty = function(obj) {
                for(var prop in obj) {
                    if(obj.hasOwnProperty(prop))
                        return false;
                }

                return true;
            };


            $scope.parse_query_listing_result = function(msg) {

                var contract_data = msg.listing[0];
                var key = contract_data.key;
                var contract_body = JSON.parse(contract_data.contract_body);
                console.log(contract_body.Seller);

                if(!(key in $scope.search_results)) {
                    $scope.search_results[key] = contract_body;
                }

                //$scope.search_results.push(contract_body);
                console.log('Search Results', $scope.search_results);

            }

            $scope.search_results = {};
            $scope.parse_search_result = function(msg) {
                console.log('Global Search Result', msg);
                var contract_data = msg.data;
                contract_data.key = msg.key;
                contract_data.rawContract = msg.rawContract;
                contract_data.nickname = msg.nickname;

                var contract_dupe = false;
                $.each($scope.search_results, function(index, contract) {
                    if(contract.key == msg.key) {
                        contract_dupe = true;
                    }
                });

                if(!contract_dupe) {
                    $scope.search_results.push(contract_data);
                }

                $.each($scope.search_results, function(index, contract) {

                    if (jQuery.isEmptyObject(contract.Contract.item_images)) {
                        console.log('empty object');
                        contract.Contract.item_images = "img/no-photo.png";
                    }
                });

                console.log('Search Results', $scope.search_results);

                if (!$scope.$$phase) {
                    $scope.$apply();
                }
            };

            if (Connection.websocket.readyState == 1) {
                $scope.load_page({});
            }

        }
    ]);
