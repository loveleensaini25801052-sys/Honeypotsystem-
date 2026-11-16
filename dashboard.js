function updateClock(){

const now=new Date();

document.getElementById("dateTime").innerHTML=now.toLocaleString();

}

setInterval(updateClock,1000);

updateClock();