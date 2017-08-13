#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <fcntl.h>

int base64_decode(const unsigned char *in, unsigned char *out);

int main(int arg , char* args[])
{

	if(arg!=4)
	{
		printf("参数不对!\n");
		return 0;
	}

	char szCertDN_IN[32]={0};
	strcpy(szCertDN_IN,args[3]);

	char szWriteFile[260]={0};
	strcpy(szWriteFile,args[2]);

	int nRet;
	int nLen;
	char szPath[260]={0};
	strcpy(szPath,args[1]);
	char szBff[3072]={0};
	int fd = open(szWriteFile,O_RDONLY);
	if(fd!=-1)
	{
		printf("%s已经存在\n",szWriteFile);
		close(fd);
		return 0;
	}
	fd = open(szWriteFile,O_WRONLY|O_CREAT|O_APPEND);
	if(fd==-1)
	{
		printf("创建文件%s失败！\n",szWriteFile);
		return 0;
	}


	FILE *fp = fopen(szPath,"r");
	if(fp==NULL)
	{
		printf("文件不存在:%s\n",szPath);	
		return 0;
	}


	unsigned char bSignData[2048]={0};
	char szBff_Temp[3072]={0};

	while(!feof(fp))
	{
		memset(szBff_Temp,0,3072);
		memset(bSignData,0,2048);
		memset(szBff,0,3072);
		fgets(szBff,3072,fp);

		memcpy(szBff_Temp,szBff,3072);
		
		char *p = NULL;
		p = strstr(szBff_Temp,"(signedText)=");
		if(p==NULL) 	continue;

		p += strlen("(signedText)=") ; 
		char *pTemp = strstr(p, " argument(certAuth)");
		*pTemp = '\0';

		unsigned char out[2048]={0};
		size_t size = base64_decode(p, out);
		if(size==0) 	continue;

		unsigned char *p7b = out;
		PKCS7* P7 = d2i_PKCS7(NULL,&p7b,size);
		if(!P7)		continue;

		STACK_OF(PKCS7_SIGNER_INFO) *sk = PKCS7_get_signer_info(P7);
		if(!sk)		continue;

		PKCS7_SIGNER_INFO *signinfo = sk_PKCS7_SIGNER_INFO_value(sk , 0);
		if(!signinfo) 	continue;

		X509 *cert = PKCS7_cert_from_signer_info(P7,signinfo);
		if(!cert)	continue;


  		char*  szSubName = X509_NAME_oneline(X509_get_subject_name(cert),NULL,0);
		char szDN[50]={0};
		p = strstr(szSubName,"CN=");
		pTemp = strstr(p,"/OU");
		*pTemp = '\0';
		strcpy(szDN,p+3);
		printf("DN=%s\n",szDN);
		

		if(P7) 
			PKCS7_free(P7);


		if((memcmp(szDN,szCertDN_IN,strlen(szCertDN_IN)) ==0) && (strlen(szCertDN_IN) == strlen(szDN)) )
		{
			write(fd, szBff,strlen(szBff));
		}

	}
	fclose(fp);
	close(fd);
	char szCMD[1024]={0};
	sprintf(szCMD,"chmod 777 ./%s",szWriteFile);
	shell_cmd(szCMD);
	
	return 0;
}


static const char *codes = 
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char map[256] = {
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255,
255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
 52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
  7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
 19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
 37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
 49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255 };

int base64_encode(const unsigned char *in,  unsigned long len, 
                        unsigned char *out)
{
   unsigned long i, len2, leven;
   unsigned char *p;
   len2 = 4 * ((len + 2) / 3);
   p = out;
   leven = 3*(len / 3);
   for (i = 0; i < leven; i += 3) {
       *p++ = codes[in[0] >> 2];
       *p++ = codes[((in[0] & 3) << 4) + (in[1] >> 4)];
       *p++ = codes[((in[1] & 0xf) << 2) + (in[2] >> 6)];
       *p++ = codes[in[2] & 0x3f];
       in += 3;
   }
   if (i < len) {
       unsigned a = in[0];
       unsigned b = (i+1 < len) ? in[1] : 0;
       unsigned c = 0;

       *p++ = codes[a >> 2];
       *p++ = codes[((a & 3) << 4) + (b >> 4)];
       *p++ = (i+1 < len) ? codes[((b & 0xf) << 2) + (c >> 6)] : '=';
       *p++ = '=';
   }
   *p = '\0';

   return p - out;
}

int base64_decode(const unsigned char *in, unsigned char *out)
{
	unsigned long t, x, y, z;
	unsigned char c;
	int	g = 3;

	for (x = y = z = t = 0; in[x]!=0;) {
		c = map[in[x++]];
		if (c == 255) return -1;
		if (c == 253) continue;
		if (c == 254) { c = 0; g--; }
		t = (t<<6)|c;
		if (++y == 4) {
			out[z++] = (unsigned char)((t>>16)&255);
			if (g > 1) out[z++] = (unsigned char)((t>>8)&255);
			if (g > 2) out[z++] = (unsigned char)(t&255);
			y = t = 0;
		}
	}

	return z;
}
#define MAXLINE 1024
int shell_cmd(char* cmd)
{
    char result_buf[MAXLINE] = {0};
	char command[MAXLINE] = {0};
    int rc = 0; // 用于接收命令返回值
    FILE *fp;

    //将要执行的命令写入buf
    snprintf(command, sizeof(command), cmd);

    //执行预先设定的命令，并读出该命令的标准输出
    fp = popen(command, "r");
    if(NULL == fp)
    {
   //     perror("popen failed");
        return 0;
    }
    while(fgets(result_buf, sizeof(result_buf), fp) != NULL)
    {
        //为了下面输出好看些，把命令返回的换行符去掉
        if('\n' == result_buf[strlen(result_buf)-1])
        {
            result_buf[strlen(result_buf)-1] = '\0';
        }
   //     printf("cmd[%s] output[%s]\r\n", command, result_buf);
    }

    //等待命令执行完毕并关闭管道及文件指针
    rc = pclose(fp);
    if(-1 == rc)
    {
 //       perror("close file pointer failed");
        return 0;
    }
    else
    {
//		printf("cmd[%s] subThreadExitStat[%d] cmdRetValue[%d]\r\n", command, rc, WEXITSTATUS(rc));
//		printf("cmd[%s] subThreadExitStat[%d] \r\n", command, rc);
    }

    return 1;
}


