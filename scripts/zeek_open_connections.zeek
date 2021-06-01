# Authors: Active Countermeasures
# This script is based on: https://github.com/corelight/zeek-long-connections/
# As this script was based upon the Corelight script, we are obligated to include the following:
# Copyright (c) 2017, Corelight, Inc. All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.

# (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.

# (3) Neither the name of Broala, Inc., nor the names of contributors may be 
#     used to endorse or promote products derived from this software without 
#     specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
@load base/protocols/conn
@load base/utils/time

# This is probably not so great to reach into the Conn namespace..
module Conn;

export {
    function set_conn_log_data_hack(c: connection) {
        Conn::set_conn(c, T);
    }
}

# Now onto the actual code for this script...

module LongConnection;

# Set this to the interval at which you want to alert on
# open connections. 1hr means that an open connection will
# be written to the conn_long log after 1hr has passed
# and then every hour after that until it closes (2hrs, 3hrs, 4hrs, etc.).
# Each time an entry is written, it contains the TOTAL duration and bytes
# for the connection, not the incremental from the last entry. The information
# is identical to what is written out to conn.log
const ALERT_INTERVAL = 1min;

export {
    redef enum Log::ID += { LOG };
}

redef record connection += {
    ## Offset of the currently watched connection duration by the long-connections script.
    long_conn_offset: count &default=0;
};

event zeek_init() &priority=5 {
    Log::create_stream(LOG, [$columns=Conn::Info, $path="conn_long"]);
}

function long_callback(c: connection, cnt: count): interval {

    # Check that we are at least above ALERT_INTERVAL before we start logging
    # open connections. Cuts down on disk space, processing here, and
    # downstream processing
    if ( c$duration >= ALERT_INTERVAL ) {
        Conn::set_conn_log_data_hack(c);
        Log::write(LongConnection::LOG, c$conn);

        # Poll again in another ALERT_INTERVAL
        return ALERT_INTERVAL;
    } 
    else 
        # If we aren't at ALERT_INTERVAL, come back in the time remaining between
        # the ALERT_INTERVAL and the current duration
        return ALERT_INTERVAL - c$duration;
}

event connection_established(c: connection) {
    # Check on this full connection in time specified by ALERT_INTERVAL
    ConnPolling::watch(c, long_callback, 1, ALERT_INTERVAL);
}

event partial_connection(c: connection) {
    # Check on this partial connection in time specified by ALERT_INTERVAL
    ConnPolling::watch(c, long_callback, 1, ALERT_INTERVAL);
}
