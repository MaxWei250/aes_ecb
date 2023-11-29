#include "aes.h"
//*default constructor
aes::aes()
{   
    cout << "aes::aes()" << endl;
}
//*constructor
/* aes::aes(byte_t key_matrix[Nk*4])
{
    cout << "aes::aes(byte_t *key_matrix)" << endl;
    //this->key_matrix = key_matrix;
    for (int i = 0; i < Nk*4; i++)
    {
        this->key_matrix[i] = key_matrix[i];
    }
    cout << "copy success" << endl;
} */
//*destructor
aes::~aes()
{
    cout << "aes::~aes()" << endl;
}
//*4 byte_t->1 word
word aes::byte2Word(byte_t& k1, byte_t& k2, byte_t& k3, byte_t& k4)
{
	word result(0x00000000);
	word temp;//*32bit
	temp = k1.to_ulong();  // K1
	temp <<= 24;//*k1 set high bits
	result |= temp;
	temp = k2.to_ulong();  // K2
	temp <<= 16;
	result |= temp;
	temp = k3.to_ulong();  // K3
	temp <<= 8;
	result |= temp;
	temp = k4.to_ulong();  // K4
	result |= temp;
	return result;
}
//*左移函数，n表示左移位数
void aes::LeftShift(word& temp, int n)
{
	word high, low;
	high = temp << n*8;
	low  = temp >> (32 - n*8);

	temp = high | low;
	//return high | low;
}
//*对输入word中的每一个字节进行S-盒变换
word aes::SubWord(word& sw)
{
	word temp;//*包含4个字节
	for(int i=0; i<32; i+=8)
	{
		int row = sw[i+7]*8 + sw[i+6]*4 + sw[i+5]*2 + sw[i+4];//*取出4个bit，前四位为行
		int col = sw[i+3]*8 + sw[i+2]*4 + sw[i+1]*2 + sw[i];
		byte_t val = S_Box[row][col];
		for(int j=0; j<8; ++j)
			temp[i+j] = val[j];
	}
	return temp;//*返回代换结果
}

/**
 * @description: //*T函数
 * @param {word} temp：//*输入的word 32bit 一列数据 4 byte_t
 * @param {int} round：//*轮数
 * @return {*}
 */
word aes::T(word temp, int round)
{
	LeftShift(temp, 1);
	temp = SubWord(temp);
	temp ^= Rcon[round-1];
	return temp;
}

/**
 * @description: key expansion
 * @param {byte_t} init_key
 * @param {word} exp_key
 * @return {*}
 */
void aes::KeyExpansion(string strKey,word exp_key[4*(Nr+1)])
{
	unsigned char init_key[KEYCODELENGTH];
	byte_t k1,k2,k3,k4;

	KeyStringToHex( strKey.c_str(), init_key );
	for(int i=0; i< 4*(Nr+1); ++i)//*循环4*(Nr+1)次，当为128bit的时候，循环44轮
	{
		if (i < Nk) //*前4个字直接赋值
		{
			k1 = (byte_t)init_key[4*i];
			k2 = (byte_t)init_key[4*i+1];
			k3 = (byte_t)init_key[4*i+2];
			k4 = (byte_t)init_key[4*i+3];
			exp_key[i] = byte2Word(k1, k2, k3, k4);
		}
		else if (i >= Nk && i%Nk == 0) //*发生为Nk倍数的情况
		{
			word temp = exp_key[i-1];
			temp = T(temp, i/Nk);
			exp_key[i] = temp ^ exp_key[i-Nk];
		}
		else if (i >= Nk && i%Nk == 4 && Nk == 8)//*只有aes256才会发生
		{
			exp_key[i] = SubWord(exp_key[i-1]) ^ exp_key[i-Nk];
		}
		else if(i > Nk)//*i > 4
		{
			exp_key[i] = exp_key[i-1] ^ exp_key[i-Nk];
		}
	}
}
/**
 * @description: 加密
 * @param {byte_t data[4} *
 * @param {word exp_key[4} *
 * @return {*}
 */
string aes::encrypt(string strSrc, word* exp_key,unsigned char* cipher,int size_cipher)
{
	ZBase64 tool;
	//unsigned char data_temp[strlen(strSrc.c_str())+PLAINCODELENGTH];//*因为数组是静态空间，所以主动多申请一个正常明文的空间
	unsigned char data_temp[((strlen(strSrc.c_str())%16==0) ?(strlen(strSrc.c_str())+16) \
	: ((int)(strlen(strSrc.c_str())/16)*16)+16) ], data_reg[4*4];
	word init_key[4];
	int group(0),grouplen(0);
	byte_t data[4*4];

	PlainStringToHex(strSrc.c_str(),data_temp,grouplen);

	while(grouplen--){
		col_convert(&data_temp[group*16]);
		for (int i = 0; i < 16; i++)
		{
			data[i] = (byte_t)data_temp[i+(group*16)];
		}
		
		//*第一轮
		for (int i = 0; i < 4; i++)
		{
			init_key[i] = exp_key[i];
		} 
		AddRoundKey(data, init_key);
    	//* Nr轮加密
		for (int i = 1; i < Nr; i++)
		{
			SubBytes(data);
			ShiftRows(data);
			Mix_Columns(data);
			for (int j = 0; j < 4; j++)
			{
				init_key[j] = exp_key[i * 4 + j];
			}
			AddRoundKey(data, init_key);
		}
		//*最后一轮
		SubBytes(data);
		ShiftRows(data);
		for (int i = 0; i < 4; i++)
		{
			init_key[i] = exp_key[4 * Nr + i];
		}
		AddRoundKey(data, init_key);

		for(int i = 0; i < 16; i++)
		{
			data_reg[i] = (unsigned char)data[i].to_ulong();
		}
		col_convert(data_reg);
		for(int i = 0; i < 16; i++)
		{
			cipher[i+group*16] = data_reg[i];
		}
		group ++;//*移动到下一组
	}

	return tool.Encode(cipher,size_cipher);
}
/**
 * @description: rows shift
 * @param {byte_t} state:plain text
 * @return {*}
 */
void aes::ShiftRows(byte_t state[4*4])
{
	word temp;
	for (int i = 0; i < 4; i++)
	{
		temp = byte2Word(state[i*4],state[i*4+1],state[2+i*4],state[3+i*4]);
		temp = (temp << i*8) | (temp >> (32-i*8));
		state[i*4]   = (byte_t)(temp.to_ulong() >> 3*8);
		state[i*4+1] = (byte_t)(temp.to_ulong() >> 2*8);
		state[i*4+2] = (byte_t)(temp.to_ulong() >> 1*8);
		state[i*4+3] = (byte_t)(temp.to_ulong());
	}
}

/**
 * @description: 有限域2^8乘法运算
 * @param {byte_t} a：被乘数
 * @param {byte_t} b：乘数
 * @return {*}
 */
byte_t aes::GF2_8Mul(byte_t a, byte_t b)
{
	byte_t end(0x00);
	bool hit_1(0);
	for (int i = 0; i < 8; i++)
	{
		if (b[i] == 1)
		{
			end ^= a ;
		}
		hit_1 = (a[7] == 1); 
		a <<= 1;
		if (hit_1)
		{
			a ^= (byte_t)0x1b;
		}
	}
	return end;
}

/**
 * @description: 3.列混淆
 * @param {byte_t} state
 * @return {*}
 */
void aes::Mix_Columns(byte_t state[4*4])
{
	byte_t temp[4*4];
	for (int i = 0; i < 4; i++)
	{
		temp[i] = GF2_8Mul((byte_t)0x02,state[i])^GF2_8Mul((byte_t)0x03,state[i+4])^state[i+8]^state[i+12];
		temp[i+4] = state[i]^GF2_8Mul((byte_t)0x02,state[i+4])^GF2_8Mul((byte_t)0x03,state[i+8])^state[i+12];
		temp[i+8] = state[i]^state[i+4]^GF2_8Mul((byte_t)0x02,state[i+8])^GF2_8Mul((byte_t)0x03,state[i+12]);
		temp[i+12] = GF2_8Mul((byte_t)0x03,state[i])^state[i+4]^state[i+8]^GF2_8Mul((byte_t)0x02,state[i+12]);
	}
	for (int i = 0; i < 4*4; i++)
	{
		state[i] = temp[i];
	}
}

/**
 * @description: 4.轮密钥加
 * @param {byte_t} data
 * @param {word} key
 * @return {*}
 */
void aes::AddRoundKey(byte_t data[4*4],word key[4])
{
	for (int i = 0; i < 4; i++)
	{
		word key1 = (key[i] >> 24) & (word)(0x000000ff);//*移动到低八位
		word key2 = (key[i] >> 16) & (word)(0x000000ff);
		word key3 = (key[i] >> 8)  & (word)(0x000000ff);
		word key4 = key[i] & (word)(0x000000ff); 

		data[i]   ^= (byte_t)key1.to_ulong();
		data[i+4] ^= (byte_t)key2.to_ulong();
		data[i+8] ^= (byte_t)key3.to_ulong();
		data[i+12] ^= (byte_t)key4.to_ulong();
	}
	
}
/**
 *  S盒变换 - 前4位为行号，后4位为列号
 */
void aes::SubBytes(byte_t mtx[4*4])
{
	for(int i=0; i<16; ++i)
	{
		int row = mtx[i][7]*8 + mtx[i][6]*4 + mtx[i][5]*2 + mtx[i][4];
		int col = mtx[i][3]*8 + mtx[i][2]*4 + mtx[i][1]*2 + mtx[i][0];
		mtx[i] = S_Box[row][col];
	}
}

//*将字符串转换成16进制
void aes::KeyStringToHex( const char* pSrc, unsigned char* pDest )
{
	int nSrcLen = 0;
	if( pSrc != 0 )
	{
		nSrcLen = strlen(pSrc);
		memcpy(pDest, pSrc, nSrcLen);
	}
	KeyPadding( pDest, nSrcLen );//*填充
	// region : debug
		/* cout << "KeyStringToHex: " << endl;
		for(int i = 0; i < KEYCODELENGTH; i++)
		{
			cout << hex << (int)pDest[i] << " ";
		}
		cout << endl;
		return ; */
	// endregion : debug
}
//*填充模式：PKCS7
void aes::KeyPadding( unsigned char* pSrc, int nSrcLen )
{
	if( nSrcLen < KEYCODELENGTH )
	{
		unsigned char ucPad = KEYCODELENGTH - nSrcLen;//*填充的字节数
		for( int nID = KEYCODELENGTH; nID > nSrcLen; --nID )
		{
			pSrc[nID - 1] = ucPad;
		}
	}
}
/**
 * @description: plain text to hex
 * @param {char} *pSrc
 * @param {unsigned char} *pDest
 * @param {int&} grouplen ://*表明现在有几组128bi的数据
 * @return {*}
 */
void aes::PlainStringToHex(const char *pSrc, unsigned char *pDest,int& grouplen)
{
	int nSrcLen = 0;
	if( pSrc != 0 )
	{
		nSrcLen = strlen(pSrc);//*输入plain text的长度
		memcpy(pDest, pSrc, nSrcLen);
	}
	PlainPadding( pDest, nSrcLen );//*填充
	grouplen = (nSrcLen/PLAINCODELENGTH) + 1; //*计算有几组128bit的数据
}
/**
 * @description: 按照填充模式PKCS7进行解密
 * @param {unsigned char*} pSrc
 * @param {int} srcLen
 * @param {int&} plainLen
 * @return {*}
 */
string aes::InvPlainPadding(unsigned char* pSrc,int srcLen,int& plainLen)
{
	bool flag(0);
	unsigned char temp(0);
	string str;

	for(int i = 0; i < srcLen; i++)
	{
		if(pSrc[i] == srcLen - i ) //*判断是否为填充数据
		{
			flag = 1;
			temp = pSrc[i];
			plainLen = i ;
		}
		else if ((flag==1) && (pSrc[i] == temp))
		{
			flag = 1;
		}
		else if(flag==1)
        {
            flag = 0;
            plainLen = 0;
        }
        //cout << "i is " << dec << i << "  " << "pSrc[i] is " << hex << (int)pSrc[i] << endl;
	}
    //cout << "plain_len is "<< dec << (int)plain_len << endl;
	for(int i = 0; i < plainLen; i++)
	{
		str += pSrc[i];
	}
	return str;
}
/**
 * @description: //*psk7 padding for plain text
 * @param {unsigned char} *pSrc:
 * @param {int} nSrcLen
 * @return {*}
 */
void aes::PlainPadding(unsigned char *pSrc, int nSrcLen)
{
	if ((nSrcLen%PLAINCODELENGTH) < PLAINCODELENGTH)//*不是整数倍
	{
		unsigned char ucPad = PLAINCODELENGTH - (nSrcLen%PLAINCODELENGTH);
		for (int nID = (((nSrcLen/PLAINCODELENGTH)+1)*PLAINCODELENGTH);  \
		nID > (nSrcLen%PLAINCODELENGTH)+((nSrcLen/PLAINCODELENGTH)*PLAINCODELENGTH); --nID)
		{
			pSrc[nID - 1] = ucPad;
		}
	}
	else if ((nSrcLen%PLAINCODELENGTH) == 0)//*整数倍
	{
		unsigned char ucPad = 0x10;
		for(int i = 0; i < PLAINCODELENGTH; i++)
		{
			pSrc[nSrcLen+i-1] = ucPad;
		}
	}
}
//*行列转换
void aes::col_convert(unsigned char mtx[4*4])
{
	unsigned char temp[4*4];
	for (int i = 0; i < 4; i++)
	{
		temp[i] =    mtx[i*4];
		temp[i+4] =  mtx[i*4+1];
		temp[i+8] =  mtx[i*4+2];
		temp[i+12] = mtx[i*4+3];
	}
	for (int i = 0; i < 4*4; i++)
	{
		mtx[i] = temp[i];
	}
}
void aes::byte_col_convert(byte_t mtx[4*4])
{
	byte_t temp[4*4];
	for (int i = 0; i < 4; i++)
	{
		temp[i] =    mtx[i*4];
		temp[i+4] =  mtx[i*4+1];
		temp[i+8] =  mtx[i*4+2];
		temp[i+12] = mtx[i*4+3];
	}
	for (int i = 0; i < 4*4; i++)
	{
		mtx[i] = temp[i];
	}
}
//*byte转char
void aes::byte2char(byte_t *mtx, unsigned char *mtx_char, int mtx_len)
{
	for (int i = 0; i < mtx_len; i++)
	{
		*mtx_char = (unsigned char)(*mtx).to_ulong();
		mtx++;
		mtx_char++;
	}
}
/**
 * @description: inv substitution transformation
 * @param {byte_t mtx[4} *
 * @return {*}
 */
void aes::InvSubBytes(byte_t mtx[4 * 4])
{
	for(int i=0; i<16; ++i)
	{
        //2^3*x^3+2^2*x^2+2^1*x^1+2^0*x^0
		int row = mtx[i][7]*8 + mtx[i][6]*4 + mtx[i][5]*2 + mtx[i][4];
		int col = mtx[i][3]*8 + mtx[i][2]*4 + mtx[i][1]*2 + mtx[i][0];
		mtx[i] = Inv_S_Box[row][col];
	}
}
/**
 * @description: right shift rows
 * @param {byte_t} state
 * @return {*}
 */
void aes::InvShiftRows(byte_t state[4*4])
{
	word temp;
	for (int i = 0; i < 4; i++)
	{
		temp = byte2Word(state[i*4],state[i*4+1],state[2+i*4],state[3+i*4]);
		temp = (temp >> i*8) | (temp << (32-i*8));
		state[i*4]   = (byte_t)(temp.to_ulong() >> 3*8);
		state[i*4+1] = (byte_t)(temp.to_ulong() >> 2*8);
		state[i*4+2] = (byte_t)(temp.to_ulong() >> 1*8);
		state[i*4+3] = (byte_t)(temp.to_ulong());
	}
}
/**
 * @description: inv mix colums
 * @param {byte_t} mtx
 * @return {*}
 */
void aes::InvMixColumns(byte_t mtx[4*4])
{
	byte_t arr[4];
	for(int i=0; i<4; ++i)
	{
		for(int j=0; j<4; ++j)
			arr[j] = mtx[i+j*4];

		mtx[i]    = GF2_8Mul(0x0e, arr[0]) ^ GF2_8Mul(0x0b, arr[1]) ^ GF2_8Mul(0x0d, arr[2]) ^ GF2_8Mul(0x09, arr[3]);
		mtx[i+4]  = GF2_8Mul(0x09, arr[0]) ^ GF2_8Mul(0x0e, arr[1]) ^ GF2_8Mul(0x0b, arr[2]) ^ GF2_8Mul(0x0d, arr[3]);
		mtx[i+8]  = GF2_8Mul(0x0d, arr[0]) ^ GF2_8Mul(0x09, arr[1]) ^ GF2_8Mul(0x0e, arr[2]) ^ GF2_8Mul(0x0b, arr[3]);
		mtx[i+12] = GF2_8Mul(0x0b, arr[0]) ^ GF2_8Mul(0x0d, arr[1]) ^ GF2_8Mul(0x09, arr[2]) ^ GF2_8Mul(0x0e, arr[3]);
	}
}
/**
 * @description: decrypt one group 128bit data
 * @param {unsigned char} cipher_group
 * @param {word} exp_key
 * @param {unsigned char*} plain_group
 * @param {int} group
 * @return {*}
 */
void aes::group_decrypt(unsigned char cipher_group[4*4],word exp_key[4*(Nr+1)],unsigned char* plain_group,int group)
{
	byte_t data[4*4];
	word init_key[4];
	col_convert(cipher_group);

	for(int i = 0; i < 16; i++)
	{
		data[i] = (byte_t)cipher_group[i];
	}

	for (int i = 0; i < 4; i++)
	{
		init_key[i] = exp_key[4*Nr+i];
	}
	AddRoundKey(data, init_key);
	for (int i = Nr-1; i > 0; i--)
	{
		InvShiftRows(data);
		InvSubBytes(data);
		for (int j = 0; j < 4; j++)
		{
			init_key[j] = exp_key[i * 4 + j];
		}
		AddRoundKey(data, init_key);
		InvMixColumns(data);
	}
	InvShiftRows(data);
	InvSubBytes(data);
	for (int i = 0; i < 4; i++)
	{
		init_key[i] = exp_key[i];
	}
	
	AddRoundKey(data, init_key);

	byte_col_convert(data);


	for(int i = 0; i < 16; i++)
	{
		plain_group[i] = (unsigned char)data[i].to_ulong();
	}
}
/**
 * @description: decrypt
 * @param {string} strSrc:base64 cipher
 * @param {word exp_key[4} *
 * @param {unsigned char*} plaintext
 * @param {int&} plainLen
 * @return {*}plain string
 */
string aes::decrypt(string strSrc, word exp_key[4 * (Nr + 1)],unsigned char* plaintext,int& plainLen)
{
	ZBase64 tool;
	int cipher_len(0);
	unsigned char group_data[16];//*src is cipher(16*x)
	int group(0),group_len(0);
	string strPlain;
	string cipher_str = tool.Decode(strSrc.c_str(),strSrc.size(),cipher_len);
	
	memcpy(plaintext,cipher_str.c_str(),strlen(cipher_str.c_str()));

	group_len = cipher_len/16;

	while(group_len--){
		for(int i = 0; i < 16; i++)
		{
			group_data[i] = plaintext[i+(group*16)];
		}
		group_decrypt(group_data,exp_key,&plaintext[group*16],group);
		group ++;
	}

	strPlain=InvPlainPadding(plaintext,strlen(cipher_str.c_str()),plainLen);
	
	return strPlain;
}
