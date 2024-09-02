set environment for convenience:

  $ [ -n "$TEST_BIN_DIR" ] && export PATH="$TEST_BIN_DIR:$PATH"
  $ alias homebus='valgrind --quiet --leak-check=full homebus'

check usage:

  $ homebus
  Usage: homebus [<options>] <command> [arguments...]
  Options:
   -s <socket>:\t\tSet the unix domain socket to connect to (esc)
   -t <timeout>:\t\tSet the timeout (in seconds) for a command to complete (esc)
   -S:\t\t\tUse simplified output (for scripts) (esc)
   -v:\t\t\tMore verbose output (esc)
   -m <type>:\t\t(for monitor): include a specific message type (esc)
  \t\t\t(can be used more than once) (esc)
   -M <r|t>\t\t(for monitor): only capture received or transmitted traffic (esc)
  
  Commands:
   - list [<path>]\t\t\tList objects (esc)
   - call <path> <method> [<message>]\tCall an object method (esc)
   - subscribe <path> [<path>...]\tSubscribe to object(s) notifications (esc)
   - listen [<path>...]\t\t\tListen for events (esc)
   - send <type> [<message>]\t\tSend an event (esc)
   - wait_for <object> [<object>...]\tWait for multiple objects to appear on homebus (esc)
   - monitor\t\t\t\tMonitor homebus traffic (esc)
  
  [1]

  $ homebus-san
  Usage: homebus-san [<options>] <command> [arguments...]
  Options:
   -s <socket>:\t\tSet the unix domain socket to connect to (esc)
   -t <timeout>:\t\tSet the timeout (in seconds) for a command to complete (esc)
   -S:\t\t\tUse simplified output (for scripts) (esc)
   -v:\t\t\tMore verbose output (esc)
   -m <type>:\t\t(for monitor): include a specific message type (esc)
  \t\t\t(can be used more than once) (esc)
   -M <r|t>\t\t(for monitor): only capture received or transmitted traffic (esc)
  
  Commands:
   - list [<path>]\t\t\tList objects (esc)
   - call <path> <method> [<message>]\tCall an object method (esc)
   - subscribe <path> [<path>...]\tSubscribe to object(s) notifications (esc)
   - listen [<path>...]\t\t\tListen for events (esc)
   - send <type> [<message>]\t\tSend an event (esc)
   - wait_for <object> [<object>...]\tWait for multiple objects to appear on homebus (esc)
   - monitor\t\t\t\tMonitor homebus traffic (esc)
  
  [1]

check monitor command:

  $ homebus monitor
  Failed to connect to homebus
  [255]

  $ homebus-san monitor
  Failed to connect to homebus
  [255]
