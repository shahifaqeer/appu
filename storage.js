
// Storage to local unlimited storage.
// None of the sensitive data is stored here.

// I am maintaining this because on Chrome on MacOS, a call to
// get all keys currently on harddisk does not succeed for extention Appu.
// Works for other sample extention that I wrote to test this feature and also works
// on other platforms (Win, Linux) for Appu extention. For now, this is a workaround.
var storage_meta = {
    "storage_meta" : []
};


function print_storage_keys() {
    for (var i = 0; i < storage_meta.storage_meta.length; i++) {
	console.log("APPU DEBUG: " + (i+1) + ". Key: '" + storage_meta.storage_meta[i] + "'");
    }
    print_storage_size();
}

function init_storage_meta() {
    read_from_local_storage("storage_meta", function(rc) {
	    if (rc != undefined &&
		JSON.stringify(rc) != JSON.stringify({})) {
		storage_meta = rc;
	    }
	});
}

// Initialize function to create data["account_sites"] object
// in chrome.storage which maintains a mapping of 8-byte site hashes
// TODO shift everything to all account sites instead of nuas
function init_visited_sites() {
    read_from_local_storage("visited_sites", function(data) {
        if (!("visited_sites" in data)) {
            data["visited_sites"] = {}
            write_to_local_storage(data)
        }
    });
}

function cb_print(msg) {
    if (msg == undefined) {
	msg = "APPU DEBUG: (localStorage callback)";
    }
    return function (rc) {
        if (rc != undefined) {
            msg += JSON.stringify(rc)
		}
        console.log(msg);
    }
}

function print_storage_size() {
    get_storage_size(cb_print("APPU DEBUG: (localStorage callback) Local Storage Size: "));
}

function get_storage_size(cb) {
    return chrome.storage.local.getBytesInUse(null, cb);
}

function expunge_local_storage() {
    var b = storage_meta["storage_meta"].slice();
    for (var i = 0; i < b.length; i++) {
	delete_from_local_storage(b[i]);
    }
    // chrome.storage.local.clear(cb);
}

function write_to_local_storage(data) {
    chrome.storage.local.set(data);

    data_key = Object.keys(data)[0];
    if (storage_meta["storage_meta"].indexOf(data_key) == -1) {
	storage_meta["storage_meta"].push(data_key);
    }
    chrome.storage.local.set(storage_meta);
}

function read_from_local_storage(key, cb) {
    if (cb == undefined) {
	cb = cb_print("APPU DEBUG: Reading from local storage key: " + key + "\n")
    }
    chrome.storage.local.get(key, cb);
}

function delete_from_local_storage(key) {
    chrome.storage.local.remove(key);

    storage_meta["storage_meta"].splice(storage_meta["storage_meta"].indexOf(key), 1);
    chrome.storage.local.set(storage_meta);
}

init_storage_meta();
init_visited_sites();
