set environment for convenience:

  $ [ -n "$TEST_BIN_DIR" ] && export PATH="$TEST_BIN_DIR:$PATH"
  $ alias homebusd='valgrind --quiet --leak-check=full homebusd'

check usage:

  $ homebusd -h
  homebusd: invalid option -- 'h'
  Usage: homebusd [<options>]
  Options: 
    -A <path>:\t\tSet the path to ACL files (esc)
    -s <socket>:\t\tSet the unix domain socket to listen on (esc)
  
  [1]

  $ homebusd-san -h
  homebusd-san: invalid option -- 'h'
  Usage: homebusd-san [<options>]
  Options: 
    -A <path>:\t\tSet the path to ACL files (esc)
    -s <socket>:\t\tSet the unix domain socket to listen on (esc)
  
  [1]
