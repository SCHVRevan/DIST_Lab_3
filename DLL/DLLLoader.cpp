#include <Windows.h>
#include <winerror.h>
#include <tchar.h>

int main()
{
    // You also specify the complete path.
    LoadLibrary(_T("VirusDLL.dll"));
    return 0;
}
