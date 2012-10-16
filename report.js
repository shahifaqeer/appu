
function send_report() {
    message = {};
    message.type = "send_report";
    message.report = $("#report").val();
    chrome.extension.sendMessage("", message, function() {});
    $("#report").val("");    
    $("#send").hide();
    $("#status").append("<p>Report Sent</p>");
    return false;
}

function delete_report_entry() {
    console.log("Here here:");
    var report_entry = $(this).parent().parent().index();
    $(this).parent().parent().remove();
    var message = {};
    message.type = "delete_report_entry";
    message.report_entry = report_entry - 1;
    chrome.extension.sendMessage("", message);
}

function populate_report(report) {
    try {
	if (report.length) {
	    for(var i = 0; i < report.length; i++) {
		var nr = $('<tr class="report-entry"></tr>');
		var incident = report[i];
		var incident_time = new Date(incident.now);
		var incident_site = incident.site;
		var incident_other_sites = incident.other_sites;
		
		var ntd = $('<td></td>');
		$(ntd).text(incident_time.toDateString() + "," + incident_time.toLocaleTimeString());
		$(nr).append(ntd);
		
		ntd = $('<td></td>');
		$(ntd).text(incident_site);
		$(nr).append(ntd);
		
		ntd = $('<td></td>');
		var npr = $('<p></p>');
		$(npr).text(incident_other_sites.pop());
		$(ntd).append(npr);
		$(nr).append(ntd);

		for(var j = 0; j < incident_other_sites.length; j++) {
		    npr = $('<p></p>');
		    $(npr).text(incident_other_sites[j]);
		    $(ntd).append(npr);
		}

		ntd = $('<td></td>');
		var nimg_src = '<img id="re-'+ i +'" class="report-entry-delete" src="images/cross-mark.png" height="22">';
		var nimg = $(nimg_src);
		$(ntd).append(nimg);
		$(nr).append(ntd);

		$("#password-reuse-warning-report-table-body").append(nr);
	    }
	}
	else {
	    $("#password-reuse-warning-report-table").remove();
	    $("#page-wrap").append($('<p id="no-report">No warnings generated yet</p>'));
	}
    }
    catch (err) {
	console.log("Error occurred while creating table: " + err);
    }
    if(!report.length) {
	$("#send").hide()
    }
}

document.addEventListener('DOMContentLoaded', function () {
    var message = {};
    message.type = "get_report";
    chrome.extension.sendMessage("", message, populate_report);
    $("#send").bind("click", function() { send_report()});
    $("#accordion").accordion({
	collapsible: true,
	active: false,
	heightStyle: "content"
    });
    $("#password-reuse-warning-report").on("click", ".report-entry-delete", delete_report_entry);
});
