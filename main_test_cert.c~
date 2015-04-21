#include "miracl/miracl.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <assert.h>
#include <dirent.h>


#define MOD_TAM 1000
#define PUBKEY_ALGO_LEN 1000

#define TYPE_PEM 0
#define TYPE_DER 1
#define TIPO_CUSTOM 3

#define TAM_MODULE 600
#define NUM_DIGITOS_MIRACL 2000
#define BASE_MIRACL 16

//site importante:
//http://www.mobilefish.com/services/rsa_key_generation/rsa_key_generation.php

//warning variavel global
int setDebug = 0;

typedef struct t_certificate{
	char filename[300];
	char module[TAM_MODULE];
	int certType;
}t_certificate;

typedef struct aresta{
	char mdc[TAM_MODULE];
	int no1;
	int no2;
}aresta;

typedef struct listaCert{
	t_certificate cert;
	struct listaCert* next;
	struct listaCert* prev;
}listaCert;


big MDC(big x, big y){
	//inicializar miracl
	miracl *mip = mirsys(NUM_DIGITOS_MIRACL, BASE_MIRACL);
	big xd = mirvar(0);
	big yd = mirvar(0);
	big mdcResult = mirvar(0);
	mip->IOBASE = 16;
	
	xgcd(x,y,xd,yd,mdcResult);
		
	mip->IOBASE = 10;
	system("clear");
	printf("mdc dos modulos!\n");
	cotnum(mdcResult,stdout);
	getchar();
	
	return mdcResult;
}


char* mdcComStrings(char* x, char* y,char* result){
	//inicializar miracl
	miracl *mip = mirsys(NUM_DIGITOS_MIRACL, BASE_MIRACL);
	mip->IOBASE = 16;
	big xd = mirvar(0);
	big yd = mirvar(0);
	big mdcResult = mirvar(0);
	
	big xBig = mirvar(0);
	big yBig = mirvar(0);
	
	cinstr(xBig,x);
	cinstr(yBig,y);
	
	if(setDebug){
		printf("Fazendo o mdc com strings\n");
	}
	
	xgcd(xBig,yBig,xd,yd,mdcResult);
	
// 	if(setDebug){
// 		system("clear");
// 		printf("mdc dos modulos!\n");
// 		cotnum(mdcResult,stdout);
// 		getchar();
// 	}
	
	int len = cotstr(mdcResult,result);
	
	assert(len != 0);
	
	return result;
}


char* analisarHeadPem(char* head,char* metadado){
	int i = 0;
	int j = 0;
	
	while(head[i] != '\0'){
		if(i<5){
			if(head[i] != '-'){
				//algo errado, não eh um pem
				return NULL;
			}
		}
		else if(head[i] != '-'){
			metadado[j] = head[i];
			j++;
		}
		
		i++;
	}
	metadado[j] = '\0';
	
	return metadado;
}

char* getExtension(char* nomeArquivo,char* extensao){
	int i = 0;
	int j = 0;
	int pegarExt = 0;
	
	while(nomeArquivo[i] != '\0'){
		if(pegarExt){
			extensao[j] = nomeArquivo[i];
			j++;
		}
		if(nomeArquivo[i] == '.'){
			pegarExt = 1;
			j = 0;
		}
		i++;
	}
	extensao[j] = '\0';
	
	return extensao;
}

int extensaoReconhecida(char* ext){
	if(!strcmp(ext,"der") || !strcmp(ext,"custom") || !strcmp(ext,"cer") || !strcmp(ext,"crt") || !strcmp(ext,"pem") || !strcmp(ext,"PEM")){
		return 1;
	}else{
		return 0;
	}
}

char* getModulo(X509* cert,char* modulus){
	char pubkey_algoname[PUBKEY_ALGO_LEN];
	RSA *rsa_key;
	char *rsa_e_dec, *dsa_p_hex;
	
	int pubkey_algonid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
	
	if (pubkey_algonid == NID_undef) {
		printf("unable to find specified public key algorithm name.\n");
	}
	
	char buf[400];
	const char* sslbuf = OBJ_nid2ln(pubkey_algonid);
	assert(strlen(sslbuf) < PUBKEY_ALGO_LEN);
	strncpy(buf, sslbuf, PUBKEY_ALGO_LEN);
	
	if (pubkey_algonid == NID_rsaEncryption) {
		
		EVP_PKEY *pkey = X509_get_pubkey(cert);
		if(pkey == NULL){
			printf("unable to extract public key from certificate");
		}
		
		
		rsa_key = pkey->pkey.rsa;
		if(rsa_key == NULL){
			printf("unable to extract RSA public key");
		}
		rsa_e_dec = BN_bn2dec(rsa_key->e);
		if(rsa_e_dec == NULL){
			printf("unable to extract rsa exponent");
		}
		modulus = BN_bn2hex(rsa_key->n);
		if(modulus == NULL){
			printf("unable to extract rsa modulus");
		}
		
		EVP_PKEY_free(pkey);
	}
		
	return modulus;
	
}


int verificarHexa(char* string){
	int i = 0;
	int flag = 1;
	char aux;
	while(string[i] != '\0'){
		aux = string[i];
		if(!(aux >= '0' && aux <= '9') && !(aux >= 'A' && aux <= 'F') && !(aux >= 'a' && aux <= 'f')){
			flag = 0;	
		}
		i++;
	}
	return flag;
}

//recebe e faz o parsing dos certificados, se tudo certo retorna 0, else retorna 1 pra indicar erro nos arquivos retorna
//retorna 2 indicando extensao nao reconhecida
//retorna 3 indicando erro ao pegar os modulos
t_certificate inicializaCertificado(char* cert1,char* diretorio){
	FILE* cert1Fp;
	char cert1Ext[100];
	int cert1isBin;
	int k;
	char diretorioBackup[200];
	int i;
	
	if(setDebug){
		printf("entrou na inicializacao de cert\n");
		
	}
	
	//inicializar miracl
	miracl *mip = mirsys(NUM_DIGITOS_MIRACL, BASE_MIRACL);
	big bigModulo = mirvar(0);
	mip->IOBASE = 16;
	
	t_certificate certResult;
	t_certificate certVazio;
	
	
	strcpy(diretorioBackup,diretorio);
	
	
	//arrumar o diretorio
	char diretorioAux[300];
	char fullFilename[400];
	
	strcpy(diretorioAux,strcat(diretorio,"/"));
	strcpy(fullFilename,strcat(diretorioAux,cert1));
	
	strcpy(diretorio,diretorioBackup);
	
	
	
	
	int getModules = 0;
	
	//definir certificado vazio
	strcpy(certVazio.filename,"");
	strcpy(certVazio.module,"0");
	certVazio.certType = -1;
	
	strcpy(cert1Ext,getExtension(cert1,cert1Ext));
	
	
	
	if(!extensaoReconhecida(cert1Ext)){
		printf("ext nao reconhecida\n");
		return certVazio;
	}
	
	if(!strcmp(cert1Ext,"PEM") || !strcmp(cert1Ext,"pem") || !strcmp(cert1Ext,"custom")){
		cert1isBin = 0;
	}else{
		cert1isBin = 1;
	}
	
	
	//cuidado, alteraçao dee abrir arquivo
	cert1isBin = 0;
	
	//abrir o arquivo do jeito correto
	if(cert1isBin){
		cert1Fp = fopen(fullFilename,"rb");
		
	}else{
		cert1Fp = fopen(fullFilename,"r");
		
	}
	
	if(cert1Fp == NULL){
		printf("nao abriu direito o certificado na funçao inicializaCertificado\n");
		return certVazio;
	}
	
	char modulo[MOD_TAM];
	
	int tipoCert;
	if(!strcmp(cert1Ext,"crt") || !strcmp(cert1Ext,"der") || !strcmp(cert1Ext,"cer")){
		//processar arquivo der
		tipoCert = TYPE_DER;
		
		X509 *certDer = d2i_X509_fp(cert1Fp, NULL);
		
		if(!certDer){
			fclose(cert1Fp);
			printf("problema ao ler certificado der, %s\n",cert1);
			return certVazio;
		}else{
			getModulo(certDer,modulo);
			if(verificarHexa(modulo)){
				cinstr(bigModulo,modulo);
				getModules++;
			}else{
				printf("Modulo der recebido errado, caracteres invalidos, %s\n",cert1);
				getchar();
			}
		}
	}
	
	
	if(!strcmp(cert1Ext,"custom")){
		if(setDebug){
			printf("Tipo custom\n");
		}
		tipoCert = TIPO_CUSTOM;
		
		fgets(modulo,2000,cert1Fp);
		
		printf("%s\n",modulo);
		assert(verificarHexa(modulo));
		getModules++;
	}
	
	
	if(setDebug && tipoCert == TIPO_CUSTOM){
		printf("Tipo custom feito\n");
	}
	
	
	
	if(!strcmp(cert1Ext,"PEM") || !strcmp(cert1Ext,"pem")){
		//processar arquivo PEM
		tipoCert = TYPE_PEM;
		
		X509 *certa = (X509 *)PEM_read_X509(cert1Fp, NULL, NULL, NULL);
		if (!certa) {
			fclose(cert1Fp);
			printf("nao leu o certificado x509\n");
			return certVazio;
		}else{
			//parsing de boas
			getModulo(certa,modulo);
			//printf("modulus:\n%s\n",modulo);
			if(verificarHexa(modulo)){
				cinstr(bigModulo,modulo);
				getModules++;
			}else{
				printf("Modulo PEM recebido errado, caracteres invalidos, %s\n",cert1);
				getchar();
			}
		}
		
	}
	
	
	if(getModules != 1){
		printf("nao pegou o modulo return vazio, %s\n",cert1);
		return certVazio;
	}else{
		strcpy(certResult.filename,cert1);
		strcpy(certResult.module,modulo);
		certResult.certType = tipoCert;
		return certResult;
	}
	
}




//recebe e faz o parsing dos certificados, se tudo certo retorna 0, else retorna 1 pra indicar erro nos arquivos retorna
//retorna 2 indicando extensao nao reconhecida
//retorna 3 indicando erro ao pegar os modulos
int recebeCertificados(char* cert1, char* cert2){
	FILE* cert1Fp;
	FILE* cert2Fp;
	char cert1Ext[100];
	char cert2Ext[100];
	int cert1isBin;
	int cert2isBin;
	
	strcpy(cert1Ext,getExtension(cert1,cert1Ext));
	strcpy(cert2Ext,getExtension(cert2,cert2Ext));
	
	
	if(!extensaoReconhecida(cert1Ext) || !extensaoReconhecida(cert2Ext)){
		return 2;
	}
	
	if(!strcmp(cert1Ext,"PEM") || !strcmp(cert1Ext,"pem")){
		cert1isBin = 0;
	}else{
		cert1isBin = 1;
	}
	
	if(!strcmp(cert2Ext,"PEM") || !strcmp(cert2Ext,"pem")){
		cert2isBin = 0;
	}else{
		cert2isBin = 1;
	}
	//abrir o arquivo do jeito correto
	if(cert1isBin){
		cert1Fp = fopen(cert1,"rb");
		
	}else{
		cert1Fp = fopen(cert1,"r");
		
	}
	
	
	//abrir o arquivo 2 do jeito correto
	if(cert2isBin){
		cert2Fp = fopen(cert2,"rb");
		
	}else{
		cert2Fp = fopen(cert2,"r");
		
	}

	
	if(cert1Fp == NULL || cert2Fp == NULL){
		return 1;
	}
	
	if(!strcmp(cert1Ext,"crt") || !strcmp(cert1Ext,"der")){
		//processar arquivo der
		
		
	}
	
	//inicializar miracl
	miracl *mip = mirsys(NUM_DIGITOS_MIRACL, BASE_MIRACL);
	big mdcResult = mirvar(0);
	big x = mirvar(0);
	big y = mirvar(0);
	mip->IOBASE = 16;
	
	int getModules = -1;
	
	if(!strcmp(cert1Ext,"PEM") || !strcmp(cert1Ext,"pem")){
		//processar arquivo PEM
		X509 *certa = (X509 *)PEM_read_X509(cert1Fp, NULL, NULL, NULL);
		if (!certa) {
			fclose(cert1Fp);
			return 2;
		}else{
			//parsing de boas
			char* modulo;
			modulo = getModulo(certa,modulo);
			printf("modulus:\n%s\n",modulo);
			getchar();
			
			
			cinstr(x,modulo);
			getModules++;
		}
		
	}
	
	
	
	if(!strcmp(cert2Ext,"PEM") || !strcmp(cert2Ext,"pem")){
		//processar arquivo PEM
		X509 *certb = (X509 *)PEM_read_X509(cert2Fp, NULL, NULL, NULL);
		if (!certb) {
			fclose(cert2Fp);
			return 2;
		}else{
			//parsing de boas
			char* modulo2;
			modulo2 = getModulo(certb,modulo2);
			printf("modulus:\n%s\n",modulo2);
			getchar();
			
			
			cinstr(y,modulo2);
			getModules++;
		}
		
	}
	
	if(getModules == 1){
		MDC(x,y);
	}
	else{
		return 3;	
	}
	
	return 0;
}

void printarArestas(aresta* vetorDeArestas,int tam){
	int i;
	aresta arestaAtual;
	big valorDoMod = mirvar(0);
	
	printf("Mostrando o valor das arestas!!!!\n\n");
	for(i=0;i<tam;i++){
		arestaAtual = vetorDeArestas[i];
		printf("Aresta: %d -> %d\n",arestaAtual.no1,arestaAtual.no2);
		cinstr(valorDoMod,arestaAtual.mdc);
		printf("Valor do mdc entre os dois nós:\n");
		cotnum(valorDoMod,stdout);
		printf("\n\n");
	}
	printf("Fim das arestas\n");
	
}


//retorna erros para serem analizados
int recebeDiretorio(char* diretorio){
	DIR* dirAtual;
	struct dirent *arquivo;
	listaCert *certAux;
	int i;
	int numNos;
	int numArestas;
	
	miracl *mip = mirsys(NUM_DIGITOS_MIRACL, BASE_MIRACL);
	
	if((dirAtual = opendir(diretorio)) == NULL){
		return 1;
	}
	
	numNos = 0;
	while((arquivo = readdir(dirAtual)) != NULL){
		if(strcmp(arquivo->d_name,"..") && strcmp(arquivo->d_name,".")){
			numNos++;
		}
	}
	
	t_certificate *certificadosVetor = (t_certificate*) calloc(numNos,sizeof(t_certificate));
	if(certificadosVetor == NULL){
		printf("erro no calloc\n");
		
	}
	
	numArestas = (numNos * (numNos - 1)) / 2;
	
	aresta* arestasVetor = (aresta*) calloc(numArestas,sizeof(aresta));
	
	rewinddir(dirAtual);
	
	i = 0;
	while((arquivo = readdir(dirAtual)) != NULL){
		if(strcmp(arquivo->d_name,"..") && strcmp(arquivo->d_name,".")){
			strcpy(certificadosVetor[i].filename,arquivo->d_name);
			i++;
		}
	}
	
	if(setDebug){
		printf("Vai inicializar certificados\n");
		
	}
	
	//inicializa os certificados!!!
	for(i=0;i<numNos;i++){
		certificadosVetor[i] = inicializaCertificado(certificadosVetor[i].filename,diretorio);
	}
	
	if(setDebug || 1){
		printf("print dos nos:\n\n");
		for(i=0;i<numNos;i++){
			printf("<%s>\n",certificadosVetor[i].filename);
			printf("%s\n",certificadosVetor[i].module);
			printf("%d\n",certificadosVetor[i].certType);
			printf("\n");
		}
	}
	
	int j;
	//definir as arestas!!!!
	int k = 0;
	aresta arestaAux;
	char mdcResultado[TAM_MODULE];
	char moduloA[TAM_MODULE];
	char moduloB[TAM_MODULE];
	
	
	if(setDebug){
		printf("Entrou na parte de inicializar as arestas\n");
	}
	
	FILE* arquivoResult;
	
	arquivoResult = fopen("colisoes","w");
	
	for(i=0;i<numNos;i++){
		//definiar arestas a partir de j > i
		for(j = i + 1;j<numNos;j++){
			//definir aresta {i,j}
			arestaAux.no1 = i;
			arestaAux.no2 = j;
			//warning codigo denso
			//colocar o valor da aresta (mdc) na inicializacao da areta
			//recuperar o modulo de cada no
			strcpy(moduloA,certificadosVetor[i].module);
			strcpy(moduloB,certificadosVetor[j].module);
			
			if(setDebug){
				printf("Vai fazer o mdc entre %d e %d\n",i,j);
			}
			mdcComStrings(moduloA,moduloB,mdcResultado);
			if(setDebug){
				printf("Fez o mdc entre %d e %d\n",i,j);
			}
			
			if(strcmp(mdcResultado,"1")){
				fprintf(arquivoResult,"%s <-> %s == %s\n",certificadosVetor[i].filename,certificadosVetor[j].filename,mdcResultado);
			}
			
			strcpy(arestaAux.mdc,mdcResultado);
			arestasVetor[k] = arestaAux;
			k++;
		}
		
	}
	
	fclose(arquivoResult);
	
	//depois de definido as arestas printa-las
	if(setDebug){
		printarArestas(arestasVetor,k);
	}
	
	return 0;
}






//recebe 2 ou 3 argumentos, sendo que se receber 2 tem q ser help, se for 3 eh a execuçao padrao em 2 certificados
int main(int argc, char** argv){
	int erroArgumentos = 0;
	int help = 0;
	int padrao = 0;
	int codigoErroCert;
	int folder = 0;
	
	if(argc != 3 && argc != 2 && argc != 4){
		erroArgumentos = 1;	
	}else{
		if(argc == 2){
			if(!strcmp(argv[1],"-help")){
				help = 1;
			}else{
				erroArgumentos = 1;
			}
			
		}
		else if(argc == 4){
			if(strcmp(argv[3],"-debug")){
				erroArgumentos = 1;
			}
			else{
				if(!strcmp(argv[1],"-folder") || !strcmp(argv[1],"-f")){
					//processsar na pasta
					folder = 1;
				}
				else{
					padrao = 1;
				}
				setDebug = 1;
			}
		}
		else{
			if(!strcmp(argv[1],"-folder") || !strcmp(argv[1],"-f")){
				//processsar na pasta
				folder = 1;
			}
			else{
				padrao = 1;
			}
		}
	}
	
	if(erroArgumentos){
		system("clear");
		printf("Wrong arguments.\n");
		printf("Usage:\nexe certificate1.pem certificate2.pem\n");
		printf("To help:\nexe -help\n");
		return 1;
	}
	if(help){
		system("clear");
		printf("Welcome to certTest\n\n");
		printf("This program is supposed to test whether two or more public key certificates have commom primes in its modules\n");
		printf("Execute the program with two certificates as parameter and I take care of the rest!\n\n");
		printf("Usage:\nexe certificate1.pem certificate2.pem\n");
		printf("To help:\nexe -help\n");
		return 1;
	}
	if(padrao){
		codigoErroCert = recebeCertificados(argv[1],argv[2]);
	}
	int erroDiretorio;
	if(folder){
		erroDiretorio = recebeDiretorio(argv[2]);
	}
	
	if(erroDiretorio == 1){
		system("clear");
		printf("The folder specified do not exist\n");
		return 1;
	}
	
	//analisar os codigos de erro de receber certificados
	if(codigoErroCert == 0){
		
	}
	if(codigoErroCert == 1){
		system("clear");
		printf("Input files dont exist.\n");
		return 1;
	}
	if(codigoErroCert == 2){
		system("clear");
		printf("File extensions not supported!\n");
		printf("The input files should be .pem, .der, .cer or .crt\n");
		return 1;
		
	}
	if(codigoErroCert == 3){
		system("clear");
		printf("Couldnt read public keys modules\n");
		return 1;
	}
	
	return 0;
}	