var cache = initialize_cache()

function init_user_account_sites_entry(username, username_length, username_reason) {
    var uas_entry = {};
    uas_entry.num_logins = 0;
    uas_entry.pwd_unchanged_duration = 0;
    uas_entry.pwd_stored_in_browser = 'donno';
    uas_entry.num_logouts = 0;
    uas_entry.latest_login = 0;

    //In case of aggrgate_data, this field contains the
    //actual username used to log into that site.
    //In case of current_report, this field contains an
    //alias of actual username. For e.g. "john.smith" would
    //get replaced by "username23".
    //For this, we use pii_vault.aggregate_data.pi_field_value_identifiers
    //This will take care of anonymizing the fields in current_report
    uas_entry.username = username;
    uas_entry.username_reason = username_reason;
    uas_entry.username_length = username_length;

    //Values could be 'yes', 'no', 'maybe'
    uas_entry.am_i_logged_in = 'no';
    //Specifically naming it with prefix "my_" because it was
    //creating confusion with current_report.pwd_groups (Notice 's' at the end)
    uas_entry.my_pwd_group = 'no group';
    uas_entry.tts = 0;
    uas_entry.tts_login = 0;
    uas_entry.tts_logout = 0;
    uas_entry.site_category = 'unclassified';
    return uas_entry;
}

function init_non_user_account_sites_entry() {
    var non_uas_entry = {};
    non_uas_entry.latest_access = 0;
    non_uas_entry.tts = 0;
    non_uas_entry.site_category = 'unclassified';
    return non_uas_entry;
}

function initialize_report() {
    var current_report = {};

    //Current report initialized
    current_report.initialize_time = new Date();

    //Current report: Id
    current_report.reportid = pii_vault.config.reportid;

    //Current report: Device Id
    current_report.deviceid = pii_vault.config.deviceid;

    //Current report: is it modified?
    current_report.report_modified = "no";
    //Current report: GUID
    current_report.guid = pii_vault.guid;
    current_report.num_report_visits = 0;
    current_report.report_time_spent = 0;

    //Errors generated during this reporting period.
    //Send them out for fixing
    current_report.appu_errors = [];

    //Has user viewed "My Footprint" page since
    //last report? Shows general curiosity and tech savvyness on behalf of
    //user. Also tells us how engaging appu is.
    current_report.num_myfootprint_visits = 0;
    current_report.myfootprint_time_spent = 0;

    //Current report: was it reviewed?
    //Necessary because even if report sending is set to auto, a person
    //still might do review.
    current_report.report_reviewed = false;

    //Current report - Has user 'explicitly' approved it to be sent out?
    //This is either "false" or the timestamp of user approval.
    //In case report_setting is manual, then it is equal to scheduled_reporting_time.
    current_report.user_approved = false;

    // ** Following entry is totally experimental and most likely would be
    //    DEPRECATED in the future releases **
    //Sites where users have been entering inputs.
    //Its only use is for Appu to detect the kind of
    //inputs that users have been entering and where.
    //Also, if the input type is TEXT or similar, then length of the data
    //entered
    //Each entry is of the form:
    // [1, new Date(1354966002000), 'www.abc.com', 'test', 'button', 'length'],
    // Very first entry is the unique record number useful for deletion.
    // Second is timestamp
    // Third name of the site
    // Fourth name of the input field
    // Fifth type of the input field - text, textarea, button etc
    // Sixth length of the input field
    current_report.input_fields = [];

    //Current report - How many attempts it took to send the report
    //                 to the server?
    // (This could be because either stats servers were down OR
    //  user was not connected to the Internet)
    current_report.send_attempts = [];

    //Current report - What was the extension version at the time of
    //                 this report?
    current_report.extension_version = pii_vault.config.current_version;

    //Current report - Was there a version update event in between?
    current_report.extension_updated = false;

    //Current report - Is the report structure updated?
    //This is useful so that if user has opened REPORTS page,
    //he will get dynamic 'aggregate' updates every 5 minutes.
    //Table row updates are sent asynchronously whenever they happen
    current_report.report_updated = false;

    //Scheduled time for this report
    current_report.scheduled_report_time = pii_next_report_time();
    //Actual send report time for this report
    current_report.actual_report_send_time = 'Not delivered yet';

    //"auto", "manual" or "differential"
    current_report.report_setting = pii_vault.options.report_setting;

    //"participating", "not-participating"
    current_report.lottery_setting = pii_vault.options.lottery_setting;

    //How many times did user hit "remind me later" for this report?
    current_report.send_report_postponed = 0;
    //Total unique sites accessed since the last report
    //But don't actually enlist those sites
    current_report.num_total_sites = 0;
    //Total time spent on each site
    current_report.total_time_spent = 0;
    current_report.total_time_spent_logged_in = 0;
    current_report.total_time_spent_wo_logged_in = 0;

    //Sites with user's account that users have logged into
    //since last report
    current_report.num_user_account_sites = 0;

    //Each site is a record such as
    // username + ':' + site_name --> Primary Key
    // tts = Total Time Spent
    // tts_login = Total Time Spent Logged In
    // tts_logout = Total Time Spent Logged out
    // num_logins = Number of times logged in to a site
    // num_logouts = Number of times logged out of a site explicitly
    // latest_login = Last login time in the account
    // pwd_group = To group by sites using same password
    // site_category = Type of the site
    // A function init_user_account_sites_entry() gives the empty value for each site
    current_report.user_account_sites = {};

    //Sites where user does not have account (but "log in" is present)
    //Once again don't enlist those sites
    current_report.num_non_user_account_sites = 0;

    //Number of times appu was disabled.
    //and how long each time
    current_report.appu_disabled = [];

    //New list of sites added to dontbuglist since last report
    current_report.dontbuglist = [];

    //Number of different passwords used since the last report
    current_report.num_pwds = 0;

    // Password group name, sites in each group and password strength
    // Key: "Grp A" etc
    // Value: {
    //    'sites' : Array of domains,
    //    'strength' : Array of pwd strength,
    // }
    // Since this field gets sent to the server, I don't store full_pwd_hash here.
    // That value is stored in aggregate_data.pwd_groups
    current_report.pwd_groups = {};

    //Similarity distance between each different password
    //Each entry is like {"pwd_group_0" : [{ "pwd_group_1" : 23}, { "pwd_group_2" : 14}]}
    current_report.pwd_similarity = {};

    //Downloaded PI from following sites
    //Each entry is like: {'site_name' : { download_time: xyz, downloaded_fields: [a, b, c]}}
    current_report.downloaded_pi = {};

    //Fields that share common values across sites
    //Each entry is like: {'field_name' : ['site_1', 'site_2', 'site_3']} etc
    //One has to consult aggregate stats for this.
    current_report.common_fields = {};

    //Finally our old pwd_reuse_warnings
    //Each record is of the following form:
    //[1, 1355555522298, 'aaa.com', 'bbb.com, ggg.com'],
    // First entry is the unique identifier to delete the record.
    // Second is timestamp
    // Third is site where user was warned on
    // Fourth is list of sites for which user was warned
    current_report.pwd_reuse_warnings = [];

    var environ = voodoo.ua();
    //General info about user's environment
    current_report.browser = environ.browser.name;
    current_report.browser_version = environ.browser.version;
    current_report.os = environ.platform.os;
    current_report.os_version = environ.platform.version;
    current_report.layout_engine = environ.browser.engine;
    current_report.layout_engine_version = environ.browser.engineVersion;

    return current_report
}

//Aggregate data is gathered over the time unlike daily reports.
//Also aggregate data will contain sensitive data such as per_site_pi
//that is not sent to the server. Only user can view it from "My Footprint"
function initialize_aggregate_data() {
    var aggregate_data = {};

    // This stores which sites are currently in the logged-in status.
    // Since multiple users cannot sign into the same site without
    // removing cookies for others, we can have only site-name as key
    // instead of having username+sitename.
    // (However, have to check how many users create chrome-profiles)
    // Whenever a successful login event is triggered, we record
    // what are the session cookies for this site.
    // cookie_key = domain + path + ":" + cookie_name
    // The structure will be:
    // site_name : {
    //               username : 'john.doe',
    //               tot_http_requests_since_login : 0,
    //               tot_http_responses_since_login : 0,
    //               cookies :
    //                        'session_cookie_key_1':
    //                               {
    //                                 cookie_class : 'before', 'during', or 'after',
    //                                 hashed_cookie_value : sha1sum(actual_cookie_value),
    //                                 num_http_responses_cookie_unchanged:
    //                                 current_state: 'present', 'absent', 'changed'
    //                                 session_cookie : between 0 and 1.
    //                               }
    //              }
    // 1. Cookie_class:
    // 'during': for cookies that are set explicitly during a successful login process.
    // 'before': for cookies cookie that are created even before a successful login.
    //           That may mean that its not a necessary cookie for detecting
    //           login-state. However, depending on the server, its still possible for a cookie
    //           in this class to get different value after logging-in.
    // 'after':  cookie was set after successful login and hence is not related to detecting login-state.
    // Some initial observations: For facebook, all session cookies get class 'during'
    // For github and amazon, all session cookies get class 'before'. That is they exist even before
    // you login.
    // 2. hashed_cookie_value:
    //    Just to see if server changes the value of the cookie and how often. Probably that
    //    would indicate which cookies are session cookies even if all the cookies have class
    //    'before'. Hypothesis here is that session cookies would have one constant value.
    //    Something like a session-id. Indeed in case of Github, I see a cookie named 'logged_in'
    //    with a value "yes" if user has signed in.
    //    Although its completely possible that a site changes session cookies with each request
    //    for extra security.
    // 3. session_cookie:
    //    1 indicates that Appu is sure that its a session cookie
    //    0 indicates that Appu is sure that its not a session cookie.
    //    Any value in between tells the Appu's belief that the cookie is a session cookie.
    //    Need to devise some good parameters to calculate posterior beliefs.
    aggregate_data.session_cookie_store = {};

    // Records if one is logged-in to any particular site at the moment.
    // If so, what is the username identifier (such as username1) used.
    // e.g. google.com : {
    //                     logged-in: yes,
    //                     username: "xyz"
    //                   }
    aggregate_data.current_loggedin_state = {};

    //When was this created?
    aggregate_data.initialized_time = new Date();
    //Is user aware? How many times is he reviewing his own data?
    //This could be used as a feedback to the system about user's awareness
    //(hence an indirect metric about users' savviness) and
    //also to warn user.
    aggregate_data.num_viewed = 0;
    aggregate_data.total_time_spent = 0;

    //Stats about general sites access
    aggregate_data.num_total_sites = 0;
    aggregate_data.all_sites_total_time_spent = 0;
    aggregate_data.all_sites_stats_start = new Date();

    //Stats and data about sites with user accounts (i.e. where user logs in)
    //user_account_sites[] is an associative array with key: site_name

    //Value corresponding to that is an object with following dictionary:
    //Each site is a record such as
    // site_name --> Primary Key
    // tts = Total Time Spent
    // tts_login = Total Time Spent Logged In
    // tts_logout = Total Time Spent Logged out
    // num_logins = Number of times logged in to a site
    // num_logouts = Number of times logged out of a site explicitly
    // latest_login = Last login time in the account
    // pwd_group = To group by sites using same password
    // site_category = Type of the site
    aggregate_data.num_user_account_sites = 0;
    aggregate_data.user_account_sites = {};

    //Stats and data about sites where user browses but never logs in
    //IMPORTANT: This detailed list of sites is only maintained in aggregate stats.
    //           Its never reported to the server.
    //non_user_account_sites[] is an associative array with key: site_name
    //Value corresponding to that is an object with following dictionary:
    //site_name, last_access_time, total_time_spent, site_category
    aggregate_data.num_non_user_account_sites = 0;

    // shift this to storage_meta
    //aggregate_data.non_user_account_sites = {};

    //Passwords data
    //pwd_groups is an associative array. Key is group name and values are list of sites
    //sharing that password
    aggregate_data.num_pwds = 0;

    // Password group name, sites in each group and password strength
    // Key: "Grp A" etc
    // Value: {
    //    'sites' : Array of domains,
    //    'strength' : Array of pwd strength,
    //    'full_hash' : A million times rotated hash value of salted passwd,
    // }
    aggregate_data.pwd_groups = {};
    aggregate_data.pwd_similarity = {};

    //Per site PI downloaded
    //Key: site name
    //Values: time downloaded
    // field_name --> field value
    aggregate_data.per_site_pi = {};

    //This is used to assign a unique identifier to
    //each possible value of PI.
    //For eg. an address like "122, 5th ST SE, ATLANTA 30318, GA, USA" will
    //get an identifier like "address1"
    //Or a name like "Appu Singh" will get an identifier like "name3"
    //This is useful to show in reports page (so that the real values are
    // shown in the tooltip). Also it helps to always assign a unique
    //identifier even if that thing is downloaded multiple times over the
    //time.
    aggregate_data.pi_field_value_identifiers = {};

    return aggregate_data;
}

// contains visited sites information and stats for quick access
// on miss, data is loaded from storage. if not in storage, data is created
// sync cache to storage every 10 mins and clean it up every 10 hours by
// deleting old entries and only keeping latest 90 entries.

function initialize_cache() {
    var cache = {};
    cache.visited_sites = {};
    cache.site_stats = {};
    return cache;
}

//---------------------- START of CODE to MANAGE NON-USER-ACCOUNT SITES ---
// NUAS: NON USER-ACCOUNT SITES, Uses bloom filter and chrome.storage

// TODO call this function to initialize storage_meta.aggragate_data
function init_non_user_account_sites() {
    aggregate_data.non_user_account_sites = {};
    return aggregate_data
}

// Perhaps I should create a class or a closure to deal with this shit
// but then so far I have not used it (except a few callbacks), and just
// plain old procedural programming seems good enough for now.

// n: Assuming a user would have 10000 different nuas sites.
// k: 10 hash functions
// p: false positive rate: 1.0E-10
// Substituting: 1 / (1 - (1 - p ** (1 / k)) ** (1 / (k * n)))
// Size of BF ~ 1MB = 1048576

// var total_chunks = 1024;
// var chunk_size = 1024;
// var total_hash_funcs = 10;

var total_chunks = 100;
var chunk_size = 100;
var total_hash_funcs = 5;

function init_nuas_bf() {
    var bf_size = total_chunks * chunk_size;
    var ab = new ArrayBuffer(bf_size);

    pii_vault.nuas_bf = ab;
    pii_vault.nuas_bf_byteview = new Uint8Array(ab);
    pii_vault.num_nuas_bf = 0;
}

function flush_num_nuas_bf() {
    var write_key = pii_vault.guid + ":nuas_bf:num_nuas_bf";
    localStorage[write_key] = JSON.stringify(pii_vault.num_nuas_bf);
}

function read_num_nuas_bf() {
    var read_key = pii_vault.guid + ":nuas_bf:num_nuas_bf";
    pii_vault.num_nuas_bf = JSON.parse(localStorage[write_key]);
}

function flush_nuas_bf_to_disk() {
    flush_num_nuas_bf();
    for (var i = 0; i < total_chunks; i++) {
	flush_buffer_chunk(i+1);
    }
}

function read_nuas_bf_from_disk() {
    init_nuas_bf();
    read_num_nuas_bf();
    for (var i = 0; i < total_chunks; i++) {
	var temp_buf = read_buffer_chunk(i+1);
	byte_start_index = i * chunk_size;
	for (var j = 0; j < chunk_size; j++) {
	    pii_vault.nuas_bf_byteview[byte_start_index + j] = temp_buf[j];
	}
    }
}

// //Following 2 functions are from: http://updates.html5rocks.com/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
// //I modified them to use Uint8Array instead of Uint16Array
// function ab2str(buf) {
//     return String.fromCharCode.apply(null, new Uint8Array(buf));
// }

// function str2ab(str) {
//     var buf = new ArrayBuffer(str.length);
//     var bufView = new Uint8Array(buf);

//     for (var i=0, strLen=str.length; i<strLen; i++) {
// 	bufView[i] = str.charCodeAt(i);
//     }

//     return buf;
// }

// guid:nuas_bf:0-1023
// guid:nuas_bf:1024-2047
// Chunk number starts from 1,2, .., 1024
function flush_buffer_chunk(chunk_number) {
    //Extract buffer as per the chunk number.
    start_index = (chunk_number - 1) * chunk_size;
    //Last index is non-inclusive
    end_index = start_index + chunk_size;
    flush_buf = pii_vault.nuas_bf_byteview.subarray(start_index, end_index);
    flush_buf_str = ab2str(flush_buf);
    var write_key = pii_vault.guid + ":nuas_bf:" + start_index + "-" + (end_index-1);
    localStorage[write_key] = JSON.stringify(flush_buf_str);
}

function read_buffer_chunk(chunk_number) {
    //Extract buffer as per the chunk number.
    start_index = (chunk_number - 1) * chunk_size;
    //Last index is non-inclusive
    end_index = start_index + chunk_size;
    var read_key = pii_vault.guid + ":nuas_bf:" + start_index + "-" + (end_index-1);
    var read_buf_str = JSON.parse(localStorage[read_key]);
    var temp_bufview = new Uint8Array(str2ab(read_buf_str));
    return temp_bufview;
}

var bit_set_array = {
    '0': 128,
    '1': 64,
    '2': 32,
    '3': 16,
    '4': 8,
    '5': 4,
    '6': 2,
    '7': 1,
};

function get_bits(bit_numbers) {
    var val_bit_numbers = [];

    for (var i = 0; i < bit_numbers.length; i++) {
	byte_number = Math.floor(bit_numbers[i]/8);
	byte_bit_number = bit_numbers[i] % 8;
	if (bit_numbers[i] > 7) {
	    byte_number += 1;
	}

	val_bit_numbers.push(pii_vault.nuas_bf_byteview[byte_number] & bit_set_array[byte_bit_number]);
    }
    return val_bit_numbers;
}

//Accepts an array containing bit numbers to be set.
function set_bits(bit_numbers) {
    var chunks_array = {};
    for (var i = 0; i < bit_numbers.length; i++) {
	byte_number = Math.floor(bit_numbers[i]/8);
	byte_bit_number = bit_numbers[i] % 8;
	if (bit_numbers[i] > 7) {
	    byte_number += 1;
	}

	if (pii_vault.nuas_bf_byteview[byte_number] != 0) {
	    console.log("APPU DEBUG: Byte number(" + byte_number + ") already has some bits set:");
	}

	pii_vault.nuas_bf_byteview[byte_number]	|= bit_set_array[byte_bit_number];
	var chunk_number = Math.floor(byte_number/total_chunks) + 1;
	chunks_array[chunk_number] = true;
    }
    for (var k in chunks_array) {
	flush_buffer_chunk(k);
    }
}

function url_to_bits(url) {
    var hash_bit_numbers = [];

    var hash1_str = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(url));
    var hash1 = parseInt(hash1_str.substring(hash1_str.length - 10, hash1_str.length), 16);

    var hash2_str = CryptoJS.SHA1(url).toString();
    var hash2 = parseInt(hash2_str.substring(hash2_str.length - 10, hash2_str.length), 16);

    var max_bit_number = total_chunks * chunk_size * 8;
    for (var i = 1; i <= total_hash_funcs; i++) {
	var curr_hash_bit_number = (hash1 + i * hash2) % max_bit_number;
	hash_bit_numbers.push(curr_hash_bit_number);
    }
    return hash_bit_numbers;
}

function is_url_counted(url, bit_numbers) {
    var val_bit_numbers = get_bits(bit_numbers);
    if (val_bit_numbers.reduce(function(a, b) { return a + b }) != 10) {
	return false;
    }
    return true;
}

function add_url_to_nuas_bf(url) {
    var bit_numbers = url_to_bits(url);
    if (is_url_counted(url, bit_numbers)) {
	return;
    }

    set_bits(bit_numbers);
    pii_vault.num_nuas_bf += 1;
    flush_num_nuas_bf();
}

//Following adds a site that does not have user account to aggregate data.
//By adding I mean it adds only 8 bytes of sha256 sum. This is easier
//than maintaining bloom filter.

/*
function subtract_ad_non_uas(domain) {
    var etld = get_domain(domain);
    var tmp = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(etld));
    var etld_hash = tmp.substring(tmp.length - 8, tmp.length);

    load_nuas(etld_hash, (function(site_hash) {
        return function(data) {
            if (!("non_user_account_sites" in data)) {
                //do nothing
                console.log("APPU DEBUG: no non_user_account_sites")
            } else if (!(site_hash in data["non_user_account_sites"])) {
                //do nothing
                console.log("APPU DEBUG: no site_hash " + site_hash + "non_user_account_sites")
            } else {
                console.log("APPU DEBUG: remove " + site_hash + " from non_user_account_sites")
                delete data["non_user_account_sites"][site_hash]
                write_to_local_storage(data)

                pii_vault.aggregate_data.num_non_user_account_sites -= 1;
	            flush_selective_entries("aggregate_data", ["num_non_user_account_sites"]);
            }
        }
    }(etld_hash)));
}

function add_ad_non_uas(domain) {
    var etld = get_domain(domain);
    var tmp = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(etld));
    var etld_hash = tmp.substring(tmp.length - 8, tmp.length);

    load_nuas(etld_hash, (function(site_hash) {
        return function(data) {
            if (!("non_user_account_sites" in data)) {
                data["non_user_account_sites"] = {}
                console.log("APPU DEBUG: Create non_user_account_sites")
            }
            if (!(site_hash in data["non_user_account_sites"])) {
                console.log("APPU DEBUG: Add "+ site_hash +" to non_user_account_sites")
                data["non_user_account_sites"][site_hash] = true
                write_to_local_storage(data)
                pii_vault.aggregate_data.num_non_user_account_sites += 1;
	            flush_selective_entries("aggregate_data", ["num_non_user_account_sites"]);
            }
        }
    }(etld_hash)));
}
*/

// **** BEGIN - Investigation state load/offload functions
// This is to unlimitedStorage.
// None of the sensitive data is stored here.

function add_visited_site(domain) {
    var etld = get_domain(domain);
    var tmp = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(etld));
    var etld_hash = tmp.substring(tmp.length - 8, tmp.length);

    // TODO include parameters time_spent in sec, Date.now()
    offload_visited_site_info(etld_hash)
}

function initialize_visited_site_object() {
    site_obj = {}
    site_obj["num_visits"] = 0
    site_obj["tot_time_spent"] = 0
    site_obj["latest_visit"] = 0
    return site_obj
}

function update_visited_site_object(site_obj, time_spent_in_this_session, timestamp_now) {
    if (!("num_visits" in site_obj)) {
        site_obj = initialize_visited_site_object(site_obj)
    }
    site_obj["num_visits"] += 1
    site_obj["tot_time_spent"] += time_spent_in_this_session
    site_obj["latest_visit"] = timestamp_now
    return site_obj
}

// TODO create functions to flush bookkeeping object every 10 hours
// TODO functions to check bookkeeping.visited_sites
function update_pii_vault_aggregate_data_counters(etld_hash) {
    pii_vault.aggregate_data.num_total_sites += 1
    //pii_vault.bookkeeping.visited_sites[etld_hash] = true
}

function offload_visited_site_info_callback(site_hash, timespent, now) {
    return function(data) {
        if (!(site_hash in data["visited_sites"])) {
            // increase num_visits += 1, tot_time_spent += delta_time, latest_visit = now()
            data["visited_sites"][site_hash] = initialize_visited_site_object()
            update_pii_vault_aggregate_data_counters(site_hash)
            console.log("APPU DEBUG: create " + site_hash + " object; "+ JSON.stringify(data["visited_sites"][site_hash]))
        }
        update_visited_site_object(data["visited_sites"][site_hash], timespent , now)
        write_to_local_storage(data)
        console.log("APPU DEBUG: updated " + site_hash + " object; "+ JSON.stringify(data["visited_sites"][site_hash]))
    }
}

function offload_visited_site_info(etld_hash, timespent, now) {
    timespent = typeof timespent !== 'undefined' ? timespent : 42;
    now = typeof now !== 'undefined' ? now : Date.now();
    load_visited_site_info(etld_hash, offload_visited_site_info_callback(etld_hash, timespent, now))
}

//function offload_visited_site_info(etld_hash) {
//    console.log("APPU DEBUG: Offloading visited_site info for " + etld_hash)
//    read_from_local_storage("visited_sites", (function(site_hash, timespent, now) {
//        return function(data) {
//            if (!(site_hash in data["visited_sites"])) {
//                // increase num_visits += 1, tot_time_spent += delta_time, latest_visit = now()
//                data["visited_sites"][site_hash] = initialize_visited_site_object()
//                console.log("APPU DEBUG: create " + site_hash + " object; "+ JSON.stringify(data["visited_sites"][site_hash]))
//            }
//            update_visited_site_object(data["visited_sites"][site_hash], timespent , now)
//            write_to_local_storage(data)
//            console.log("APPU DEBUG: updated " + site_hash + " object; "+ JSON.stringify(data["visited_sites"][site_hash]))
//        }
//    }(etld_hash, 0.1, 12345)));
//}

function load_visited_site_info(etld_hash, cb) {
    console.log("APPU DEBUG: Loading visited site info for " + etld_hash)
    if (cb == undefined) {
        cb = cb_print("APPU DEBUG: site info for: " + etld_hash + "\n")
    }
    read_from_local_storage('visited_sites', cb)
}

function print_visited_site_info(etld_hash) {
    load_visited_site_info(etld_hash, (function(site_hash) {
        return function(data) {
            if (!("visited_sites" in data)) {
                console.log("APPU DEBUG: no visited_sites object in storage")
            }else if (!(site_hash in data["visited_sites"])) {
                console.log("APPU DEBUG: " + site_hash + " not present in visited_sites")
            } else {
                console.log("APPU DEBUG: visited_site_info for "+ site_hash + ": " + JSON.stringify(data["visited_sites"][site_hash]))
            }
        }
    }(etld_hash)));
}

function remove_visited_site_info(etld_hash) {
    // may be useful for removing a blacklisted site added later by the user
    console.log("APPU DEBUG: Remove visited_site info for " + etld_hash)
    read_from_local_storage("visited_sites", (function(site_hash) {
        return function(data) {
            if (!(site_hash in data["visited_sites"])) {
                console.log("APPU DEBUG: " + site_hash + " not present in visited_sites")
            }
            delete data["visited_sites"][site_hash]
            write_to_local_storage(data)
            //console.log("APPU DEBUG: all site hashes after offload:" + JSON.stringify(data))
        }
    }(etld_hash)));
}


function remove_visited_sites() {
    console.log("APPU DEBUG: Cleaning visited_sites to empty object")
    read_from_local_storage("visited_sites", function(data) {
        data["visited_sites"] = {}
        write_to_local_storage(data)
    });
}
//---------------------- END of CODE to MANAGE NON-USER-ACCOUNT SITES

// This gets called from update_user_account_sites_stats() (which in turn gets called from
// bg_passwd.js after successful login) OR from "background.js" if the message is "signed_in"
// with value "yes"
function add_domain_to_uas(domain, username, username_length, username_reason) {
    var cr = pii_vault.current_report;
    var ad = pii_vault.aggregate_data;
    var site_category = 'unclassified';

    var hk = username + ":" + domain;

    if (domain in fpi_metadata) {
	site_category = fpi_metadata[domain]["category"];
    }

    if (!(hk in cr.user_account_sites)) {
	cr.user_account_sites[hk] = init_user_account_sites_entry(username, username_length, username_reason);
	cr.user_account_sites[hk].site_category = site_category;
	cr.num_user_account_sites += 1;
	flush_selective_entries("current_report", ["user_account_sites", "num_user_account_sites"]);

	if (pii_vault.total_site_list.indexOf(domain) != -1 &&
	    !(does_user_have_account(domain))) {
	    // This means that this site was counted as non user account site before.
	    // So adjust it.
	    console.log("Here here: Subtracting from num_non_user_account_sites: " + domain);
	    cr.num_non_user_account_sites -= 1;
	    flush_selective_entries("current_report", ["num_non_user_account_sites"]);
	}
    }

    //Add this site to aggregate data
    if (!(hk in ad.user_account_sites)) {
	ad.user_account_sites[hk] = init_user_account_sites_entry(username, username_length, username_reason);
	ad.user_account_sites[hk].site_category = site_category;
	ad.num_user_account_sites += 1;

	flush_selective_entries("aggregate_data", ["num_user_account_sites", "user_account_sites"]);
    }

    cr.num_non_user_account_sites = cr.num_total_sites - cr.num_user_account_sites;
    flush_selective_entries("current_report", ["num_non_user_account_sites"]);
}

// This gets called from bg_passwd.js after its clear that the login
// to this domain was successful.
function update_user_account_sites_stats(domain, username, username_length, username_reason, is_stored) {
    var cr = pii_vault.current_report;
    var ad = pii_vault.aggregate_data;
    var hk = username + ":" + domain;

    //Add this site to current report, aggregate data if already not present
    add_domain_to_uas(domain, username, username_length, username_reason);
    //Send only domain here. No need to send username or hk
    subtract_ad_non_uas(domain);

    cr.user_account_sites[hk].num_logins += 1;
    cr.user_account_sites[hk].latest_login = new Date();

    ad.user_account_sites[hk].num_logins += 1;
    ad.user_account_sites[hk].latest_login = new Date();

    if (is_stored) {
        cr.user_account_sites[hk].pwd_stored_in_browser = 'yes';
    }
    else {
        cr.user_account_sites[hk].pwd_stored_in_browser = 'no';
    }

    flush_selective_entries("current_report", ["user_account_sites"]);
    flush_selective_entries("aggregate_data", ["user_account_sites"]);
}

// current_report.input_fields = [
// 	[1, new Date(1354966002000), 'www.abc.com', 'test', 'button', 0],
function pii_log_user_input_type(message) {
    var total_entries = pii_vault.current_report.input_fields.length;
    var last_index =  total_entries ? pii_vault.current_report.input_fields[total_entries - 1][0] : 0;
    var domain_input_elements = [
	last_index + 1,
	new Date(),
	get_domain(message.domain),
	message.attr_list.name,
	message.attr_list.type,
	message.attr_list.length,
    ];
    console.log("APPU INFO: Appending to input_fields list: " + JSON.stringify(domain_input_elements));
    pii_vault.current_report.input_fields.push(domain_input_elements);
    flush_selective_entries("current_report", ["input_fields"]);

    for (var i = 0; i < report_tab_ids.length; i++) {
	chrome.tabs.sendMessage(report_tab_ids[i], {
	    type: "report-table-change-row",
	    table_name: "input_fields",
	    mod_type: "add",
	    changed_row: domain_input_elements,
	});
    }
}


// ***************** BEGIN ****************************
// Code for temporary cache of visited_sites in pii_vault
// synchronization to storage needed every 10 mins
// flush lowest used websites every 10 hours

function add_visited_site_to_cache(domain) {
    // input: domain -> calculate site_hash
    // if site_hash not in vault load_visited_site_from_storage(site_hash) into cache or create new entry
    // add site_hash to cache.visited_sites
    // update cache.site_stats

    var etld = get_domain(domain);
    var tmp = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(etld));
    var etld_hash = tmp.substring(tmp.length - 8, tmp.length);

    if (!(etld_hash in cache.visited_sites)) {
        load_visited_site_from_storage(etld_hash)
    } else {
    // not in cache but visits should be added
        update_visited_site_in_cache(etld_hash)
        update_site_stats_in_cache(1, 0, 0)
    }
    console.log("APPU DEBUG: Done adding and updating visited site " + etld_hash + " in cache")
}

function create_visited_site_in_cache(etld_hash) {
    cache.visited_sites[etld_hash] = {}
    cache.visited_sites[etld_hash]["tot_time_spent"] = 0;
    cache.visited_sites[etld_hash]["latest_visit"] = 0;
    cache.visited_sites[etld_hash]["num_visits"] = 0;
    cache.visited_sites[etld_hash]["dirty"] = 0;
    //this function only runs if site_stats does not exist already
    if (!("num_visited_sites" in cache.site_stats)) {
        create_site_stats_in_cache()
    }
    console.log("APPU DEBUG: Create new visited_site entry in cache for " + etld_hash)
}

function create_site_stats_in_cache() {
    cache.site_stats["num_visited_sites"] = 0
    cache.site_stats["num_removed_sites"] = 0
    cache.site_stats["num_user_account_sites"] = 0
    cache.site_stats["num_non_user_account_sites"] = 0
    cache.site_stats["size_visited_sites"] = 0
    cache.site_stats["dirty"] = 0
}

function update_visited_site_in_cache(etld_hash) {
    // TODO fix time_spent stuff
    if (!(etld_hash in cache.visited_sites)) {
        create_visited_site_in_cache(etld_hash)
    }
    time_spent = 0.1
    cache.visited_sites[etld_hash]["tot_time_spent"] += time_spent
    cache.visited_sites[etld_hash]["latest_visit"] = Date.now()
    cache.visited_sites[etld_hash]["num_visits"] += 1
    cache.visited_sites[etld_hash]["dirty"] = 1
    console.log("APPU DEBUG: Update visited_site entry in cache for " + etld_hash)
}

function update_site_stats_in_cache(visited_sites_increment, removed_sites_increment, user_account_sites_increment) {
    //this function will only run if site_stats does not exist already
    if (!("num_visited_sites" in cache.site_stats)) {
        create_site_stats_in_cache()
    }

    cache.site_stats["num_visited_sites"] += visited_sites_increment
    cache.site_stats["num_removed_sites"] += removed_sites_increment
    cache.site_stats["num_user_account_sites"] += user_account_sites_increment
    cache.site_stats["num_non_user_account_sites"] = cache.site_stats["num_visited_sites"] - cache.site_stats["num_user_account_sites"]
    cache.site_stats["dirty"] = 1
    console.log("APPU DEBUG: Update site_stats in cache")
}

function load_visited_site_from_storage(etld_hash) {
    //input: site_hash; if site found then load it, else create it. dirty will be 1 when it gets updated
    read_from_local_storage("visited_sites", (function(site_hash) {
        return function(data) {
            if (site_hash in data["visited_sites"]) {
                //load it to cache if it exists
                cache.visited_sites[site_hash] = data["visited_sites"][site_hash]
                cache.visited_sites[site_hash]["dirty"] = 0
                console.log("APPU DEBUG: Load " + site_hash + " info from storage.visited_sites")
            } else {
                console.log("APPU DEBUG: " + site_hash + " not present in storage.visited_sites. Create it in cache")
                //create it in cache if it doesn't exist in storage
                create_visited_site_in_cache(site_hash)
                // every time a site is added to cache.visited_sites, increment cache.site_stats.size_visited_sites
                // and visited site stats
                cache.site_stats["size_visited_sites"] += 1
                cache.site_stats["dirty"] = 1
                update_visited_site_in_cache(site_hash)
                update_site_stats_in_cache(1, 0, 0)
            }
        }
    }(etld_hash)));
}

function flush_cache_to_storage() {
    //sync dirty = 1 every 10 mins
    read_from_local_storage("site_stats", function(data) {
        if (cache.site_stats["dirty"] == 1) {
            //directly replace data["site_stats"] - no need to read it first
            data["site_stats"] = cache.site_stats
            // don't copy dirty bit
            delete data["site_stats"]["dirty"]
            write_to_local_storage(data)
            // reset dirty bit to 0
        }
        cache.site_stats["dirty"] == 0
    })

    read_from_local_storage("visited_sites", function(data) {
        // read info from cache and find entries with dirty bits set
        for (var hash_key in cache.visited_sites) {
            if (cache.visited_sites.hasOwnProperty(hash_key)) {
                var obj = cache.visited_sites[hash_key];
                if (obj['dirty'] == 1) {
                    //copy obj to data["visited_sites"]
                    data["visited_sites"][hash_key] = obj;
                    // make sure you delete the dirty bit from storage
                    delete data["visited_sites"][hash_key]["dirty"]
                    // reset dirty bit to 0 after copy
                    obj["dirty"] = 0;
                }
            }
        }
        write_to_local_storage(data)
    })
    console.log("APPU DEBUG: Flush cache to storage at time " + Date.now())
}

function clear_extra_visited_sites_from_cache(MAX_SIZE_VISITED_SITES) {
    console.log("APPU DEBUG: Make sure you run flush_cache_to_storage() before clearing!")
    // remember to run flush before running this function!
    MAX_SIZE_VISITED_SITES = typeof MAX_SIZE_VISITED_SITES !== 'undefined' ? MAX_SIZE_VISITED_SITES : 100;
    // every 10 hours remove visited sites >= limit which have lowest latest_visit times
    if (cache.site_stats.size_visited_sites >= MAX_SIZE_VISITED_SITES) {
        console.log("APPU DEBUG: Number of visited_sites in cache = " + cache.site_stats.size_visited_sites)
        //console.log("APPU DEBUG: Length of visited_sites in cache = " + Object.keys(cache.visited_sites).length)
        // loop over all cache.visited_sites and keep adding [time:site_hash] to deletables object
        var sortable = [];
        for (var hash_key in cache.visited_sites) {
            if (cache.visited_sites.hasOwnProperty(hash_key)) {
                sortable.push([hash_key, cache.visited_sites[hash_key]["latest_visit"]])
            }
        }
        sortable.sort(function(a, b) {return a[1] - b[1]});
        var removable = sortable.slice(0,-1 * MAX_SIZE_VISITED_SITES);
        console.log("APPU DEBUG: Top sites to be removed are: "+ JSON.stringify(removable))
        for (var indx_num in removable) {
            site_hash = removable[indx_num][0]
            delete cache.visited_sites[site_hash]
        }
        cache.site_stats.size_visited_sites = MAX_SIZE_VISITED_SITES
    }
    console.log("APPU DEBUG: New length of visited_sites in cache should be " + cache.site_stats.size_visited_sites + " but is " + Object.keys(cache.visited_sites).length)
}

// TODO untested
function expunge_visited_sites_cache() {
    console.log("APPU DEBUG: Expunge visited_sites from cache")
    cache["visited_sites"] = {}
}

// TODO untested
function remove_visited_site_from_cache(etld_hash) {
    console.log("APPU DEBUG: Remove visited_site from cache for " + etld_hash)
    delete cache.visited_sites[etld_hash]
    cache.site_stats.size_visited_sites -= 1
}

// TODO untested
function remove_visited_site_from_storage(etld_hash) {
    // may be useful for removing a blacklisted site added later by the user
    console.log("APPU DEBUG: Remove visited_site from storage for " + etld_hash)
    read_from_local_storage("visited_sites", (function(site_hash) {
        return function(data) {
            if (!(site_hash in data["visited_sites"])) {
                console.log("APPU DEBUG: " + site_hash + " not present in visited_sites")
            }
            delete data["visited_sites"][site_hash]
            write_to_local_storage(data)
        }
    }(etld_hash)));
}

function print_visited_sites_from_cache() {
    console.log("APPU DEBUG: Printing all visited_sites from cache")
    console.log(JSON.stringify(cache.visited_sites))
}

function print_site_stats_from_cache() {
    console.log("APPU DEBUG: Printing all visited_sites from cache")
    console.log(JSON.stringify(cache.site_stats))
}

function print_visited_sites_from_storage() {
    console.log("APPU DEBUG: Printing all visited_sites from memory")
    read_from_local_storage("visited_sites", function(data) {
        console.log(JSON.stringify(data))
    })
}

function print_site_stats_from_storage() {
    console.log("APPU DEBUG: Printing all visited_sites from memory")
    read_from_local_storage("site_stats", function(data) {
        console.log(JSON.stringify(data))
    })
}

// *********************** END ****************************
