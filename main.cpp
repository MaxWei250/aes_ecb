#include "aes.h"
#include "fstream"
#include "zbase64.h"

int main()
{
	aes tool;
    ZBase64 base64;
    string plain_str = "aaaaaaaaaaaaaaaaaaaaa";
    unsigned char cipher[((strlen(plain_str.c_str())%16==0) ?(strlen(plain_str.c_str())+16) \
	: ((int)(strlen(plain_str.c_str())/16)*16)+16)];

    cout << hex << strlen(plain_str.c_str()) << endl;
    //*密钥扩展
	tool.KeyExpansion("aaaaaaaaaaaaaaaa",tool.exp_key);
    //*加密
	tool.encrypt(plain_str,tool.exp_key,cipher);
    
    for(int i = 0; i < sizeof(cipher); i++)
    {
        cout << hex << (int)cipher[i] << " ";
    }
    cout << endl;
    
    cout << base64.Encode(cipher,sizeof(cipher))<< endl;
    return 0;
}
