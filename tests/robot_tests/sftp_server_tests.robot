*** Settings ***
Library    SftpServerLibrary

*** Test Cases ***
Upload File And Verify
    Start SFTP Server    /tmp/sftp-test-root    demo    secret123
    Connect To Server    demo    secret123
    Upload File    /tmp/local-test.txt    /remote-test.txt
    Operation Should Exist    open    /remote-test.txt
    Operation Should Succeed    open    /remote-test.txt
    [Teardown]    Stop SFTP Server
