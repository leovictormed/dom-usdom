#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <linux/memfd.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void die(const char *m) { perror(m); _exit(126); }
static int hex(unsigned char c) { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; return -1; }
static void write_all(int fd,const unsigned char *p,size_t n) {
  while(n){ssize_t w=write(fd,p,n);if(w<0&&errno==EINTR)continue;if(w<=0)die("write memfd");p+=(size_t)w;n-=(size_t)w;}
}

int main(int argc,char **argv) {
  if(argc<5||strcmp(argv[4],"--")||argv[2][0]=='/'||strstr(argv[2],"..")) { errno=EINVAL; die("usage"); }
  unsigned char expected[32];
  if(strlen(argv[3])!=64) { errno=EINVAL; die("sha256"); }
  for(int i=0;i<32;i++){int a=hex(argv[3][2*i]),b=hex(argv[3][2*i+1]);if(a<0||b<0){errno=EINVAL;die("sha256");}expected[i]=(a<<4)|b;}
  struct open_how root_how={.flags=O_PATH|O_DIRECTORY|O_CLOEXEC,
    .resolve=RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};
  int root=(int)syscall(SYS_openat2,AT_FDCWD,argv[1],&root_how,sizeof(root_how));
  if(root<0) die("openat2 root");
  struct open_how how={.flags=O_RDONLY|O_CLOEXEC,
    .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV};
  int fd=(int)syscall(SYS_openat2,root,argv[2],&how,sizeof(how));
  if(fd<0) die("openat2 executable");
  if(close(root)) die("close root");
  struct stat st; if(fstat(fd,&st)) die("fstat");
  uid_t uid=geteuid();
  if(!S_ISREG(st.st_mode)||st.st_nlink!=1||(st.st_uid!=0&&st.st_uid!=uid)
      ||(st.st_mode&(S_ISUID|S_ISGID|0022))||(st.st_mode&0111)==0
      ||st.st_size<=0||st.st_size>512*1024*1024){errno=EPERM;die("unsafe executable");}
  EVP_MD_CTX *ctx=EVP_MD_CTX_new(); unsigned char digest[32],buf[65536]; unsigned int n=0;
  if(!ctx||EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)!=1) die("EVP init");
  int image=(int)syscall(SYS_memfd_create,"usdom-authenticated-exec",MFD_CLOEXEC|MFD_ALLOW_SEALING);
  if(image<0)die("memfd_create");
  for(;;){ssize_t r=read(fd,buf,sizeof(buf));if(r<0&&errno==EINTR)continue;if(r<0)die("read");if(!r)break;if(EVP_DigestUpdate(ctx,buf,(size_t)r)!=1)die("EVP update");write_all(image,buf,(size_t)r);}
  if(EVP_DigestFinal_ex(ctx,digest,&n)!=1||n!=32) die("EVP final");
  EVP_MD_CTX_free(ctx);
  if(memcmp(digest,expected,32)){errno=EPERM;die("sha256 mismatch");}
  if(close(fd))die("close executable");
  if(fchmod(image,0500))die("fchmod memfd");
  int seals=F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE;
  int observed_seals;
  if(fcntl(image,F_ADD_SEALS,seals)<0||(observed_seals=fcntl(image,F_GET_SEALS))<0
      ||(observed_seals&seals)!=seals)die("seal memfd");
  if(lseek(image,0,SEEK_SET)<0)die("lseek memfd");
  size_t child_slots=(size_t)argc-3;
  if(child_slots>SIZE_MAX/sizeof(char *)){errno=E2BIG;die("argv");}
  char **child_argv=calloc(child_slots,sizeof(char *)); if(!child_argv)die("calloc argv");
  child_argv[0]=argv[2];
  for(int i=5;i<argc;i++) child_argv[i-4]=argv[i];
  child_argv[argc-4]=NULL;
  char *home=getenv("HOME"); if(!home||home[0]!='/'){errno=EINVAL;die("environment");}
  char home_env[4096];
  if(snprintf(home_env,sizeof(home_env),"HOME=%s",home)>=(int)sizeof(home_env)){errno=E2BIG;die("environment");}
  char *envp[]={home_env,"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL=C","RUST_BACKTRACE=0","RUST_LIB_BACKTRACE=0",NULL};
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))die("no_new_privs");
  syscall(SYS_execveat,image,"",child_argv,envp,AT_EMPTY_PATH); die("execveat");
}
