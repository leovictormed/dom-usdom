#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LAUNCHER_SUFFIX "/labs/usdom-reserve/scripts/risc0-guest-build-launcher"
#define HELPER_SHA "11fe3802e4b781fb1fbda824acaf7bce058750d758b32d701c71d3c6bc22f076"
#define MAX_AUTHORITY (1024U * 1024U)

struct builder { const char *key; const char *file; const char *sha; };
static const struct builder builders[] = {
 {"checkpoint-outer","build-checkpoint-outer-risc0-guest.sh","9f27677217b6a1db90512bcce6d209967b7af5d84e5164db95054f643b9dd533"},
 {"checkpoint-segment","build-checkpoint-segment-risc0-guest.sh","ae32e0e302b9f015d86c7bb915b7f6fccb55d824dc2b5ea6b90af196993d090b"},
 {"complete-randomx","build-complete-randomx-risc0-guest.sh","321d2cd65d2b3cde0a7dfad3c5eb83da424ee55599ec1ce2c9c0eae58bc4aee3"},
 {"economic-block","build-economic-block-risc0-guest.sh","0bda70aa94021c4810efeebbb7730e9ec7a78b25ea9613ab20da459ac162be21"},
 {"economic-chunk","build-economic-chunk-risc0-guest.sh","54311c0e9769c3404c9b64765bc57e8546a2184a4e392df62f470a1a0a8a3f08"},
 {"finalized-burn","build-finalized-burn-risc0-guest.sh","030fd1c083c712498304453af5c81b4a1a618b68760a87fc870f95869c824de5"},
 {"randomx-aggregate","build-randomx-aggregate-risc0-guest.sh","5ca384a0a308497b12ee8987654747d28cc6b87e4e58f7fb29ba27dc2f05e5d8"},
};
static volatile sig_atomic_t child_pid = -1, caught_signal = 0;
static void die(const char *m){dprintf(2,"risc0 guest launcher: %s\n",m);_exit(70);}
static void forward_signal(int sig){caught_signal=sig;if(child_pid>0)kill(-(pid_t)child_pid,sig);}
static void full_write(int fd,const void *v,size_t n){const char *p=v;while(n){ssize_t x=write(fd,p,n);if(x<0&&errno==EINTR)continue;if(x<=0)die("capability write failed");p+=x;n-=(size_t)x;}}
static void hex(const uint8_t *in,size_t n,char *out){static const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){out[2*i]=h[in[i]>>4];out[2*i+1]=h[in[i]&15];}out[2*n]=0;}
static int safe_fd(const char *path,mode_t mode,int executable){
 int raw=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat st;if(raw<0||fstat(raw,&st))die("cannot open authority input");
 if(!S_ISREG(st.st_mode)||st.st_uid!=getuid()||(st.st_mode&07777)!=mode||st.st_nlink!=1||(executable&&!S_ISREG(st.st_mode)))die("authority input identity invalid");
 int high=fcntl(raw,F_DUPFD_CLOEXEC,20);if(high<0)die("cannot reserve authority descriptor");close(raw);return high;
}
struct sha256_ctx { uint32_t h[8]; uint64_t bits; uint8_t block[64]; size_t used; };
static uint32_t rotr(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static void sha_transform(struct sha256_ctx *c,const uint8_t b[64]){
 static const uint32_t k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 uint32_t w[64];for(int i=0;i<16;i++)w[i]=((uint32_t)b[4*i]<<24)|((uint32_t)b[4*i+1]<<16)|((uint32_t)b[4*i+2]<<8)|b[4*i+3];for(int i=16;i<64;i++){uint32_t s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3),s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}
 uint32_t a=c->h[0],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7],bb=c->h[1],cc=c->h[2];for(int i=0;i<64;i++){uint32_t s1=rotr(e,6)^rotr(e,11)^rotr(e,25),ch=(e&f)^((~e)&g),t1=h+s1+ch+k[i]+w[i],s0=rotr(a,2)^rotr(a,13)^rotr(a,22),maj=(a&bb)^(a&cc)^(bb&cc),t2=s0+maj;h=g;g=f;f=e;e=d+t1;d=cc;cc=bb;bb=a;a=t1+t2;}c->h[0]+=a;c->h[1]+=bb;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}
static void sha_init(struct sha256_ctx*c){uint32_t v[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memcpy(c->h,v,sizeof(v));c->bits=0;c->used=0;}
static void sha_update(struct sha256_ctx*c,const uint8_t*p,size_t n){c->bits+=(uint64_t)n*8;while(n){size_t take=64-c->used;if(take>n)take=n;memcpy(c->block+c->used,p,take);c->used+=take;p+=take;n-=take;if(c->used==64){sha_transform(c,c->block);c->used=0;}}}
static void sha_final(struct sha256_ctx*c,uint8_t out[32]){c->block[c->used++]=0x80;if(c->used>56){memset(c->block+c->used,0,64-c->used);sha_transform(c,c->block);c->used=0;}memset(c->block+c->used,0,56-c->used);for(int i=0;i<8;i++)c->block[63-i]=(uint8_t)(c->bits>>(8*i));sha_transform(c,c->block);for(int i=0;i<8;i++){out[4*i]=c->h[i]>>24;out[4*i+1]=c->h[i]>>16;out[4*i+2]=c->h[i]>>8;out[4*i+3]=c->h[i];}}
static void sha256_fd(int fd,uint8_t out[32]){struct sha256_ctx c;sha_init(&c);if(lseek(fd,0,SEEK_SET)<0)die("authority seek failed");uint8_t b[16384];for(;;){ssize_t n=read(fd,b,sizeof(b));if(n<0&&errno==EINTR)continue;if(n<0)die("authority read failed");if(!n)break;sha_update(&c,b,(size_t)n);}sha_final(&c,out);if(lseek(fd,0,SEEK_SET)<0)die("authority rewind failed");}
static void sha_self_test(void){struct sha256_ctx c;uint8_t d[32];char actual[65];sha_init(&c);sha_update(&c,(const uint8_t*)"abc",3);sha_final(&c,d);hex(d,32,actual);if(strcmp(actual,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))die("internal SHA-256 self-test failed");}
static void require_sha(int fd,const char *expected){uint8_t d[32];char actual[65];sha256_fd(fd,d);hex(d,32,actual);if(strcmp(actual,expected))die("authority SHA-256 mismatch");}
static void require_manifest_line(int fd,const char *sha,const char *path){
 struct stat st;if(fstat(fd,&st)||st.st_size<0||(uint64_t)st.st_size>MAX_AUTHORITY)die("authority manifest size invalid");size_t n=(size_t)st.st_size;char *p=malloc(n+1);if(!p)die("allocation failed");if(lseek(fd,0,SEEK_SET)<0)die("manifest seek failed");size_t at=0;while(at<n){ssize_t x=read(fd,p+at,n-at);if(x<0&&errno==EINTR)continue;if(x<=0)die("manifest read failed");at+=(size_t)x;}p[n]=0;
 char line[PATH_MAX+70];int z=snprintf(line,sizeof(line),"%s  %s\n",sha,path);if(z<=0||(size_t)z>=sizeof(line)||!memmem(p,n,line,(size_t)z))die("authority manifest does not bind input");free(p);if(lseek(fd,0,SEEK_SET)<0)die("manifest rewind failed");
}
static void close_untrusted_fds(void){
#ifdef SYS_close_range
 if(syscall(SYS_close_range,3U,7U,0)&&errno!=ENOSYS)die("close_range failed");
 if(syscall(SYS_close_range,12U,UINT_MAX,0)&&errno!=ENOSYS)die("close_range failed");
 if(errno!=ENOSYS)return;
#endif
 struct rlimit r;if(getrlimit(RLIMIT_NOFILE,&r))die("getrlimit failed");unsigned long max=r.rlim_cur==RLIM_INFINITY?65536UL:(unsigned long)r.rlim_cur;for(unsigned long fd=3;fd<max;fd++)if(fd<8||fd>11)close((int)fd);
}
static void validate_rlimits(void){
 struct rlimit current;
 if(getrlimit(RLIMIT_CPU,&current)||current.rlim_cur!=RLIM_INFINITY||getrlimit(RLIMIT_AS,&current)||current.rlim_cur!=RLIM_INFINITY||getrlimit(RLIMIT_FSIZE,&current)||current.rlim_cur!=RLIM_INFINITY)die("restrictive inherited rlimit");
 if(getrlimit(RLIMIT_STACK,&current)||current.rlim_cur<8U*1024U*1024U||getrlimit(RLIMIT_NPROC,&current)||current.rlim_cur<64)die("insufficient inherited rlimit");
}
static void child_policy(void){
 struct rlimit core={0,0},files={1024,1024};validate_rlimits();
 if(setrlimit(RLIMIT_CORE,&core)||setrlimit(RLIMIT_NOFILE,&files))die("rlimit policy failed");
 sigset_t empty;sigemptyset(&empty);if(sigprocmask(SIG_SETMASK,&empty,NULL))die("signal mask reset failed");for(int s=1;s<NSIG;s++)if(s!=SIGKILL&&s!=SIGSTOP)signal(s,SIG_DFL);
}
static void make_path(char out[PATH_MAX],const char *root,const char *suffix){int n=snprintf(out,PATH_MAX,"%s%s",root,suffix);if(n<=0||n>=PATH_MAX)die("repository path too long");}
static void resolve_root(char self[PATH_MAX],char root[PATH_MAX],char self_sha[65]){
 ssize_t n=readlink("/proc/self/exe",self,PATH_MAX-1);struct stat st;if(n<=0||n>=PATH_MAX-1)die("cannot resolve launcher");self[n]=0;size_t a=(size_t)n,b=strlen(LAUNCHER_SUFFIX);if(a<=b||strcmp(self+a-b,LAUNCHER_SUFFIX))die("launcher path suffix invalid");memcpy(root,self,a-b);root[a-b]=0;
 if(stat("/proc/self/exe",&st)||!S_ISREG(st.st_mode)||st.st_uid!=getuid()||(st.st_mode&07777)!=0700||st.st_nlink!=1)die("launcher identity invalid");
 int fd=open("/proc/self/exe",O_RDONLY|O_CLOEXEC);if(fd<0)die("cannot open launcher identity");uint8_t d[32];sha256_fd(fd,d);hex(d,32,self_sha);close(fd);
}
static void authenticate_tree(const char *root,const struct builder *only,int *script_fd,int *helper_fd,int *authority_fd){
 char helper[PATH_MAX],authority[PATH_MAX],script[PATH_MAX],rel[PATH_MAX];make_path(helper,root,"/labs/usdom-reserve/scripts/pinned-risc0-guest-toolchain.sh");make_path(authority,root,"/labs/usdom-reserve/PROOF-PROGRAM-MANIFEST.sha256");
 int h=safe_fd(helper,0600,0),a=safe_fd(authority,0600,0);require_sha(h,HELPER_SHA);require_manifest_line(a,HELPER_SHA,"labs/usdom-reserve/scripts/pinned-risc0-guest-toolchain.sh");
 for(size_t i=0;i<sizeof(builders)/sizeof(builders[0]);i++){if(only&&only!=&builders[i])continue;int z=snprintf(rel,sizeof(rel),"labs/usdom-reserve/scripts/%s",builders[i].file);if(z<=0||z>=PATH_MAX)die("builder path too long");make_path(script,root,"/labs/usdom-reserve/scripts/");size_t used=strlen(script);if(used+strlen(builders[i].file)>=PATH_MAX)die("builder path too long");strcat(script,builders[i].file);int s=safe_fd(script,0700,1);require_sha(s,builders[i].sha);require_manifest_line(a,builders[i].sha,rel);if(only)*script_fd=s;else close(s);}
 if(script_fd&&only==NULL)*script_fd=-1;
 if(helper_fd)*helper_fd=h;else close(h);if(authority_fd)*authority_fd=a;else close(a);
}
static int finish_child(int status){child_pid=-1;if(caught_signal){signal(caught_signal,SIG_DFL);raise(caught_signal);return 128+caught_signal;}if(WIFEXITED(status))return WEXITSTATUS(status);if(WIFSIGNALED(status)){int s=WTERMSIG(status);signal(s,SIG_DFL);raise(s);return 128+s;}return 70;}
int main(int argc,char **argv){
 const struct builder *selected=NULL;const char *test_arg=NULL;char self[PATH_MAX],root[PATH_MAX],self_sha[65];int script_fd=-1,helper_fd=-1,authority_fd=-1,cap[2],status;pid_t child;
 sha_self_test();resolve_root(self,root,self_sha);validate_rlimits();
 if(argc==2&&!strcmp(argv[1],"--preflight")){authenticate_tree(root,NULL,NULL,NULL,NULL);uint8_t n[32];if(getrandom(n,sizeof(n),0)!=(ssize_t)sizeof(n))die("nonce generation failed");puts("PASS: RISC Zero guest launcher preflight");return 0;}
 if(argc==2&&!strcmp(argv[1],"--signal-self-test")){authenticate_tree(root,NULL,NULL,NULL,NULL);sigset_t blocked,old;sigemptyset(&blocked);sigaddset(&blocked,SIGTERM);sigaddset(&blocked,SIGINT);sigaddset(&blocked,SIGHUP);if(sigprocmask(SIG_BLOCK,&blocked,&old))die("signal block failed");child=fork();if(child<0)die("fork failed");if(child==0){if(setpgid(0,0))die("child process group failed");child_policy();for(;;)pause();}if(setpgid(child,child)&&errno!=EACCES)die("parent process group failed");if(getpgid(child)!=child)die("child process group identity invalid");
 child_pid=child;struct sigaction ac={0};ac.sa_handler=forward_signal;sigemptyset(&ac.sa_mask);if(sigaction(SIGTERM,&ac,NULL)||sigaction(SIGINT,&ac,NULL)||sigaction(SIGHUP,&ac,NULL)||sigprocmask(SIG_SETMASK,&old,NULL))die("signal policy failed");while(waitpid(child,&status,0)<0)if(errno!=EINTR)die("waitpid failed");return finish_child(status);}
 if(argc<2||argc>3) die("usage: risc0-guest-build-launcher BUILDER [--authority-self-test]");
 if(argc==3){if(strcmp(argv[2],"--authority-self-test"))die("invalid argument");test_arg=argv[2];}
 for(size_t i=0;i<sizeof(builders)/sizeof(builders[0]);i++) if(!strcmp(argv[1],builders[i].key)) selected=&builders[i];
 if(!selected) die("unknown builder");
 authenticate_tree(root,selected,&script_fd,&helper_fd,&authority_fd);
 uint8_t nonce[32];if(getrandom(nonce,sizeof(nonce),0)!=(ssize_t)sizeof(nonce))die("nonce generation failed");char nonce_hex[65];hex(nonce,32,nonce_hex);if(pipe2(cap,O_CLOEXEC))die("capability pipe failed");
 sigset_t blocked,old;sigemptyset(&blocked);sigaddset(&blocked,SIGTERM);sigaddset(&blocked,SIGINT);sigaddset(&blocked,SIGHUP);if(sigprocmask(SIG_BLOCK,&blocked,&old))die("signal block failed");
 child=fork();if(child<0)die("fork failed");if(child==0){char fd_env[]="USDOM_BUILD_CAP_FD=8",auth_env[]="USDOM_BUILD_AUTHORITY_FD=10",helper_env[]="USDOM_BUILD_HELPER_FD=11",builder_env[128],repo_env[PATH_MAX+32],nonce_env[96],sha_env[96],launcher_env[96];char *av[]={"/usr/bin/bash","--noprofile","--norc","/proc/self/fd/9",(char*)test_arg,NULL};char *ev[]={"PATH=/usr/bin:/bin","LC_ALL=C","LANG=C","TZ=UTC",fd_env,auth_env,helper_env,builder_env,repo_env,nonce_env,sha_env,launcher_env,NULL};
  if(setpgid(0,0))die("child process group failed");
  close(cap[1]);if(dup2(cap[0],8)<0||dup2(script_fd,9)<0||dup2(authority_fd,10)<0||dup2(helper_fd,11)<0)die("descriptor setup failed");for(int fd=8;fd<=11;fd++)if(fcntl(fd,F_SETFD,0))die("descriptor inheritance failed");close_untrusted_fds();child_policy();snprintf(builder_env,sizeof(builder_env),"USDOM_BUILD_BUILDER=%s",selected->key);snprintf(repo_env,sizeof(repo_env),"USDOM_BUILD_REPO=%s",root);snprintf(nonce_env,sizeof(nonce_env),"USDOM_BUILD_NONCE=%s",nonce_hex);snprintf(sha_env,sizeof(sha_env),"USDOM_BUILD_SCRIPT_SHA256=%s",selected->sha);snprintf(launcher_env,sizeof(launcher_env),"USDOM_BUILD_LAUNCHER_SHA256=%s",self_sha);execve("/usr/bin/bash",av,ev);die("execve bash failed");}
 if(setpgid(child,child)&&errno!=EACCES)die("parent process group failed");
 if(getpgid(child)!=child)die("child process group identity invalid");
 child_pid=child;close(cap[0]);close(script_fd);close(helper_fd);close(authority_fd);struct sigaction action={0};action.sa_handler=forward_signal;sigemptyset(&action.sa_mask);if(sigaction(SIGTERM,&action,NULL)||sigaction(SIGINT,&action,NULL)||sigaction(SIGHUP,&action,NULL)||sigprocmask(SIG_SETMASK,&old,NULL))die("signal policy failed");
 char record[320];int z=snprintf(record,sizeof(record),"USD0M-RISC0-BUILD-CAP-v2:%s:%s:%s\n",selected->key,selected->sha,nonce_hex);if(z<=0||(size_t)z>=sizeof(record))die("capability encoding failed");full_write(cap[1],record,(size_t)z);close(cap[1]);while(waitpid(child,&status,0)<0)if(errno!=EINTR)die("waitpid failed");return finish_child(status);
}
