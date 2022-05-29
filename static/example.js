$(document).ready(function(){
    //connect to the socket server.
    var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');

    //receive details from server

    socket.on('REMOVED', function(msg) {
        console.log("Received number" + msg.REMOVED);
        //maintain a list of ten numbers
        $('#Removed').html(msg.REMOVED);
    });
});