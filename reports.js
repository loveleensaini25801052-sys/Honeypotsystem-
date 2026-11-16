function searchReports() {

let input = document.getElementById("searchInput").value.toUpperCase();

let table = document.getElementById("reportTable");

let tr = table.getElementsByTagName("tr");

for (let i = 1; i < tr.length; i++) {

let td = tr[i].getElementsByTagName("td");

let found = false;

for (let j = 0; j < td.length; j++) {

if (td[j].innerHTML.toUpperCase().indexOf(input) > -1) {

found = true;

}

}

tr[i].style.display = found ? "" : "none";

}

}