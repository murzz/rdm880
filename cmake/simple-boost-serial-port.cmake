# https://github.com/ericfont/serial-port

include(FetchContent)
FetchContent_Declare(serial-port
        GIT_REPOSITORY https://github.com/ericfont/serial-port.git
        GIT_TAG v1.11
        )
FetchContent_MakeAvailable(serial-port)
