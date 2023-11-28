#include "iostream"
#include "bitset"
#include <string>
#include "aes.h"
#include "string.h"
using namespace std;

typedef bitset<8> byte;
//void PlainPadding( unsigned char* pSrc, int nSrcLen );
//void PlainStringToHex( const char* pSrc, unsigned char* pDest );
/* int main()
{
    int i;
    aes tool;
    string a = "aaaaaaaaaaaaaaa";
    tool.PlainStringToHex(a.c_str(),(unsigned char*)a.c_str(),i);
    cout << i << endl;
    for(int i = 0; i < 32; i++)
    {
        cout << hex << (int)a[i] << " ";
    }
} */
/* unsigned char* str;

void test_func(unsigned char* str)
{
    for(int i = 0; i < 16; i++)
    {
        str[i] = i;
    }
}
int main()
{

    test_func(str);
    return 0;
} */