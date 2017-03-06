static int open( const char * pathname, int flags, ... )
{
    (void)flags;

    if( pathname[0] == '/' )
    {
        SECURITY_ATTRIBUTES sa;

        sa.nLength = sizeof( SECURITY_ATTRIBUTES );
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;

        HANDLE h = CreateFileA( "\\\\.\\NETMAP", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );

        if( h == INVALID_HANDLE_VALUE )
        {
            printf( "ERROR: 0x%08X\r\n", GetLastError() );
        }

        return (int)(uintptr_t)h;
    }

    return -1;
}

static intptr_t _get_osfhandle( int h )
{
    return (intptr_t)h;
}

static int close( int fd )
{
    HANDLE h = (HANDLE)(uintptr_t)fd;

    if( h != INVALID_HANDLE_VALUE )
        CloseHandle( h );

    return 0;
}
