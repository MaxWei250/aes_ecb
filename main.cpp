#include "aes.h"
#include "fstream"
#include "zbase64.h"

int main()
{
	aes tool;
    ZBase64 base64;
    string plain_str = "aaaaaaaaaaaaaaabaaaaa";
    int plainLen = 0;
    unsigned char cipher[((strlen(plain_str.c_str())%16==0) ?(strlen(plain_str.c_str())+16) \
	: ((int)(strlen(plain_str.c_str())/16)*16)+16)];
    unsigned char plaintext[((strlen(plain_str.c_str())%16==0) ?(strlen(plain_str.c_str())+16) \
    : ((int)(strlen(plain_str.c_str())/16)*16)+16)];

    //*密钥扩展
	tool.KeyExpansion("aaaaaaaaaaaaaaaaaaaaaaaa",tool.exp_key);
    //*加密
	string base64_cipher = tool.encrypt(plain_str,tool.exp_key,cipher,sizeof(cipher));

    string strPlain = tool.decrypt(base64_cipher,tool.exp_key,plaintext,plainLen);

    cout << "cipher is " << base64.Encode(cipher,sizeof(cipher))<< endl;

    for(int i = 0; i < plainLen; i++)
    {
        cout << hex << (int)plaintext[i] << " ";
    }
    cout << endl << "plain is " << strPlain << endl;
    cout << endl;

    return 0;
}
