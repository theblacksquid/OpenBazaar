angular.module('app').service('Connection', ['$rootScope', '$timeout', function ($rootScope, $timeout) {

    var Connection = function (onMessage) {

        var socket_uri = document.URL.replace(/https?:(.*)\/html\/.*/, "ws:$1/ws");
        console.log('Started websocket:', socket_uri);
        websocket = new WebSocket(socket_uri);

        this.websocket = websocket;
        var self = this;

        websocket.onopen = function() {
            self.websocket.send(JSON.stringify({"id": 42, "command": "load_page", "params": {}}));
            self.websocket.send(JSON.stringify({"id": 42, "command": "check_order_count", "params": {}}));
            self.websocket.send(JSON.stringify({"id": 42, "command": "check_inbox_count", "params": {}}));
        };

        loadit = function() {
            setTimeout(
                function () {
                    console.log(self.websocket.readyState);
                    if (self.websocket.readyState == 1) {
                        self.websocket.send(JSON.stringify({"id": 42, "command": "load_page", "params": {}}));
                        self.websocket.send(JSON.stringify({"id": 42, "command": "check_order_count", "params": {}}));
                        self.websocket.send(JSON.stringify({"id": 42, "command": "check_inbox_count", "params": {}}));
                        //self.websocket.send(JSON.stringify({"id":42, "command":"read_log", "params":{}}));
                        return;
                    } else {
                        loadit();
                    }
                }, 5
            );
        };
        loadit();

        //window.onload = function() {
        //    alert('test');
        //    console.log(websocket);
        //    websocket.send(JSON.stringify({"id": 42, "command": "load_page", "params": {}}));
        //}

        websocket.onclose = function (evt) {
            console.log("closed", evt);
            console.log('The websocket closed unexpectedly. Refreshing.');
            window.location.reload();
        };

        websocket.onerror = function (evt) {
            console.log("error", evt);
        };

        websocket.onmessage = function (evt) {
            var data = JSON.parse(evt.data);
            //console.log("Websocket.onMessage!");
            console.log('On Message [', data.result.type, ']: ', data);
            $timeout(function () {
                $rootScope.$apply(function () {
                    onMessage(data.result);
                });
            });

        };

        console.log(self.websocket);

        this.send = function (command, msg) {
            if (msg === undefined) {
                msg = {};
            }

            var request = {
                "id": 42,
                "command": command,
                "params": msg
            };

            var message = JSON.stringify(request);
            //console.log('Connection.send ->')

            if (self.websocket.readyState == 1) {
                self.websocket.send(message);
            }
            else {
                self.websocket.onopen = function (e) {
                    self.websocket.send(message);
                };
            }

        };


    };

    var scope = $rootScope.$new(true);

    var socket = new Connection(function (data) {

        // Emit to browser
        scope.$emit('message', data);

        if (typeof data == 'object' && typeof data.type == 'string') {
            scope.$emit(data.type, data);
        }
    });

    scope.send = socket.send;
    scope.websocket = socket.websocket;

    return scope;
}]);
