#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h>
#include<errno.h>
#include<sys/ptrace.h>
#include<sys/types.h>
#include<signal.h>
#include<sys/user.h> 
#include<asm/unistd.h>
#include<linux/limits.h>
#include<fnmatch.h>
#include<sys/syscall.h>
#include<sys/stat.h>
#include<fcntl.h>
#include <glob.h>
extern int errno ;

typedef struct user_regs_struct uregs;
char *configFile = NULL;
int exec = 0;

struct sandbox{
    pid_t pid;
    int toggle;
};
unsigned long long get_regs(uregs *regs, int i){
    switch (i)
    {
    case 0:
        return regs->rdi;
        break;
    case 1:
        return regs->rsi;
        break;
    case 2:
        return regs->rdx;
        break;
    case 3:
        return regs->rcx;//check on this value
        break;

    default: return 0;
        break;
    }
}
int checkRead(int p){
    switch (p/10)
    {
    case 11:
        return 1;
        break;
    case 10:
        return 1;
        break;
    default: return 0;
        break;
    }
}
int checkWrite(int p){
    switch (p/10)
    {
    case 11:
        return 1;
        break;
    case 1:
        return 1;
        break;
    default: return 0;
        break;
    }
}
int checkReadWrite(int p){
    switch (p/10)
    {
    case 11:
        return 1;
        break;
    default: return 0;
        break;
    }
}


void sandbox_kill(struct sandbox *sandb){
	exit(1);
}
void getdata(struct sandbox *sandbox, unsigned long long *addr,char *str,int len)
{   char *laddr = str;
    union u {
        long val;
        char chars[sizeof(long)];
    }data;
    int i = 0;
    
    while(1){
        data.val = ptrace(PTRACE_PEEKDATA,sandbox->pid, *addr + (i*sizeof(long)),NULL);
        memcpy(laddr, data.chars, sizeof(long));
        if(data.chars[sizeof(long)-1]=='\0'){
        	break;
        }
        if(i>len){
        	break;
        }
        i++;
        laddr += sizeof(long);
    }
    
}

int readpermissions(char *path){
    int block = 4, rwx = 0;
	char pattern[PATH_MAX];
    char *absolutePath;
    glob_t globbuf;
    FILE *config = fopen(configFile,"r");
	while(fscanf(config, "%d %s", &rwx, pattern) != EOF) {
  		if(fnmatch(pattern, path, 0) == 0){
            printf("Inside fnmatch %s\n", path);
  			block = rwx;
            if(block == 0) block = 3; 
  		}
  	}
	fclose(config);
    return block;
}

char fpo[PATH_MAX];
char rfpo[PATH_MAX];
int handle_open(struct sandbox *sandb, uregs *regs, int index){
    int blocked = 0;
    if(sandb->toggle ==0){
            sandb->toggle =1;
            unsigned long long fileaddr = get_regs(regs, index);
            int mode = get_regs(regs, index+1);
            mode = mode & O_ACCMODE;
		    getdata(sandb, &fileaddr, fpo,(PATH_MAX/8));
		    realpath(fpo,rfpo);
            int configMode = readpermissions(rfpo);
            if(configMode !=4 && ((mode == O_RDONLY && checkRead(configMode)==0)||(mode == O_WRONLY && checkWrite(configMode)==0)||configMode == 3)){
                printf("%s\n",rfpo);
                blocked = 1;
                regs->orig_rax = -1; // set to invalid syscall
                ptrace(PTRACE_SETREGS,sandb->pid, 0, &regs);
            } 
        }else{
            sandb->toggle = 0;
        }
    return blocked;
}

char fpe[PATH_MAX];
char rfpe[PATH_MAX];
int handle_exec(struct sandbox *sandb, uregs *regs, int index){
    int blocked = 0;
    if(sandb->toggle ==0){
        printf("Comes here in exec\n");
            sandb->toggle =1;
            exec = 1;
            unsigned long long fileaddr = get_regs(regs, index);
		    getdata(sandb, &fileaddr, fpe,(PATH_MAX/8));
		    realpath(fpe,rfpe);
            //int configMode = readpermissions(rfpe);
            //printf("%s \n",rfpe);
            //if(configMode !=4 && (configMode % 10 == 0 || configMode ==3)){
                blocked = 1;
                regs->orig_rax = 0; // set to invalid syscall
                ptrace(PTRACE_SETREGS,sandb->pid, 0, &regs);
            //} 
        }else{
            printf("Comes here in exec outside\n");
            sandb->toggle = 0;
        }
    return blocked;
}
char rn1[PATH_MAX];
char rn2[PATH_MAX];
char rn3[PATH_MAX];
char rn4[PATH_MAX];
char rn1r[PATH_MAX];
char rn2r[PATH_MAX];
int handle_rename(struct sandbox *sandb, uregs *regs, int index){
    printf("It comes here inside rename\n");
    int blocked = 0;
    int first = 0, second =1;
    if (index ==1){
        first = 1;
        second = 3;
    }
    if(sandb->toggle ==0){
            exec =1;
            sandb->toggle =1;
            unsigned long long fileaddr1 = get_regs(regs, first);
            unsigned long long fileaddr2 = get_regs(regs, second);
            getdata(sandb, &fileaddr1, rn1,(PATH_MAX/8));
            getdata(sandb, &fileaddr2, rn2,(PATH_MAX/8));
		    realpath(rn1,rn1r);
            realpath(rn2,rn2r);
            int configMode1 = readpermissions(rn1r);
            int configMode2 = readpermissions(rn2r);
            if(checkWrite(configMode1) ==0 || checkWrite(configMode2)==0){
                blocked = 1;
                regs->orig_rax = -1; // set to invalid syscall
                ptrace(PTRACE_SETREGS,sandb->pid, 0, &regs);
            } 
        }else{
            sandb->toggle = 0;
        }
    return blocked;
}


/*http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
https://nullprogram.com/blog/2018/06/23/*/

void sandbox_handle_syscall(struct sandbox *sandb) {
  	int i, blocked = 0;
	uregs regs;
	if(ptrace(PTRACE_GETREGS, sandb->pid, NULL, &regs)<0) exit(1);
    switch (regs.orig_rax)
    {
    case __NR_open:
        blocked = handle_open(sandb,&regs,0);
        break;
    case __NR_openat:
        blocked = handle_open(sandb,&regs,1);
        break;
    case __NR_execve:
        blocked = handle_exec(sandb,&regs,0);
        break;
    case __NR_execveat:
        blocked = handle_exec(sandb,&regs,1);
        break;
    //case __NR_renameat2:
        //printf("Enters __NR_renameat2 \n");
        //blocked = handle_rename(sandb,&regs,1);
        //break;
    case __NR_rename:
        printf("Enters __NR_rename \n");
        blocked = handle_rename(sandb,&regs,0);
        break;
    case __NR_renameat:
        printf("Enters __NR_renameat \n");
        blocked = handle_rename(sandb,&regs,1);
        break;
    default:
        break;
    }
	

    if (blocked) {
        ptrace(PTRACE_SYSCALL, sandb->pid, 0, 0);
        waitpid(sandb->pid, 0, 0);
        regs.rax = -EACCES; // Operation not permitted
        errno = EACCES;
        ptrace(PTRACE_SETREGS, sandb->pid, 0, &regs);
    }
    
}

void sandbox_step(struct sandbox *sandb) {
    int status;
	if(ptrace(PTRACE_SYSCALL, sandb->pid, NULL, NULL) < 0) {
		if(errno == ESRCH) {
			waitpid(sandb->pid, &status, __WALL | WNOHANG);
			sandbox_kill(sandb);
		} 
		else{
			exit(1);
		}
	}	
	wait(&status);
	if(WIFEXITED(status)){
		exit(0);
	}
	if(WIFSTOPPED(status)){
		sandbox_handle_syscall(sandb);
	}
}

void sandbox_run(char **argv,struct sandbox *sandb){
    int status;
	sandb->pid = fork();
    if(sandb->pid == -1){
        printf("Fork Failure \n");
        exit(1);
    }
    if(sandb->pid ==0){
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
				exit(1);
			}
            status = execvp(argv[0], argv);
			if(status < 0){
				exit(1);
			}
    }
    wait(NULL);
    sandb->toggle = 0;
    while (1)
    {
        sandbox_step(sandb);
    }
}

int search_config_file(char *filename){
    printf("%s\n",filename);
    if(access(filename,F_OK)==0) {
        return 1;
    }
    return 0;
}

int parse_command(int argc, char **argv){
    int result = 3;
    if(argc < 2){
        exit(1);
    }
    if(strcmp(argv[1],"-c") == 0){
        if(search_config_file(argv[2])) {
            configFile = argv[2];
            result = 2;
        }
    }
    else {
        if(search_config_file(".fendrc")){
            configFile = ".fendrc";
            result = 1;
        }else{
            char *homePath = getenv("HOME");
            configFile =(char*)malloc(strlen(homePath)+strlen("/.fendrc")+1);
            strcpy(configFile,homePath);
            strcat(configFile,"/.fendrc");
            if( search_config_file(configFile)) result = 1;
        }
    }
    if(result ==3){
        printf("Must provide a config file \n");
        exit(1);
    }
    return result;
}

void sandbox_init(int argc, char **argv){
    int result = parse_command(argc,argv);
    struct sandbox sandbox;
    switch (result)
    {
    case 1:
        sandbox_run(argv+1,&sandbox);
        break;
    case 2:
        sandbox_run(argv+3,&sandbox);
        break;
    
    default:
        printf("Must Provide a config file\n");
        break;
    }
}

int main(int argc, char **argv){
    sandbox_init(argc,argv);
}