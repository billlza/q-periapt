/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_PRIVATE_FILES_WINDOWS_H
#define QPC_PRIVATE_FILES_WINDOWS_H
/* Reference application storage, separate from the SDK and its exported ABI.
 * All child opens and publication use one pinned, non-reparse private directory.
 * The supported volume boundary matches the local Windows NTFS SDK profile. */
#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

struct qpc_file_user {
    union { TOKEN_USER alignment; unsigned char bytes[sizeof(TOKEN_USER)+SECURITY_MAX_SID_SIZE]; } storage;
    PSID sid;
};
static inline int qpc_file_current_user(struct qpc_file_user *user) {
    HANDLE token=NULL;
    if(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token)) {
        if(GetLastError()!=ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) return -1;
    }
    DWORD count=0;
    int ok=GetTokenInformation(token,TokenUser,user->storage.bytes,sizeof user->storage.bytes,&count)!=0;
    if(!CloseHandle(token)) ok=0;
    if(!ok || count<sizeof(TOKEN_USER) || count>sizeof user->storage.bytes) return -1;
    user->sid=((TOKEN_USER *)user->storage.bytes)->User.Sid;
    uintptr_t start=(uintptr_t)user->storage.bytes, sid=(uintptr_t)user->sid;
    if(sid<start || sid-start>count || count-(sid-start)<8) return -1;
    size_t length=8+4*(size_t)((unsigned char *)user->sid)[1];
    if(length>SECURITY_MAX_SID_SIZE || length>count-(sid-start) || !IsValidSid(user->sid)) return -1;
    return 0;
}
static inline int qpc_file_private(HANDLE handle) {
    struct qpc_file_user user;
    if(qpc_file_current_user(&user)) return -1;
    PSID owner=NULL; PACL acl=NULL; PSECURITY_DESCRIPTOR descriptor=NULL;
    DWORD error=GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
                               &owner,NULL,&acl,NULL,&descriptor);
    int ok=error==ERROR_SUCCESS && descriptor && owner && acl;
    if(ok) ok=IsValidSecurityDescriptor(descriptor) && IsValidSid(owner) && EqualSid(owner,user.sid) && IsValidAcl(acl);
    for(DWORD i=0;ok && i<acl->AceCount;++i) {
        void *entry=NULL;
        if(!GetAce(acl,i,&entry)) { ok=0; break; }
        ACE_HEADER *header=entry;
        if(header->AceSize<16
           || (header->AceFlags & ~(OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE|NO_PROPAGATE_INHERIT_ACE|INHERIT_ONLY_ACE|INHERITED_ACE))
           || (header->AceType!=ACCESS_ALLOWED_ACE_TYPE && header->AceType!=ACCESS_DENIED_ACE_TYPE)) { ok=0; break; }
        PSID sid=&((ACCESS_ALLOWED_ACE *)entry)->SidStart;
        size_t length=8+4*(size_t)((unsigned char *)sid)[1];
        if(length>SECURITY_MAX_SID_SIZE || length>header->AceSize-8u || !IsValidSid(sid)) { ok=0; break; }
        if(header->AceType==ACCESS_ALLOWED_ACE_TYPE && !EqualSid(sid,user.sid) && !IsWellKnownSid(sid,WinLocalSystemSid)) ok=0;
    }
    if(descriptor && LocalFree(descriptor)!=NULL) ok=0;
    return ok ? 0 : -1;
}
static inline int qpc_file_information(HANDLE handle, int directory, BY_HANDLE_FILE_INFORMATION *info) {
    if(GetFileType(handle)!=FILE_TYPE_DISK || !GetFileInformationByHandle(handle,info)
       || (info->dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)
       || !!(info->dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory
       || (!directory && info->nNumberOfLinks!=1)) return -1;
    return 0;
}
static inline int qpc_file_leaf(const WCHAR *name, size_t length) {
    if(!length || length>255 || name[length-1]==L'.' || name[length-1]==L' ') return -1;
    for(size_t i=0;i<length;++i)
        if(name[i]<32 || wcschr(L"\"*/:<>?\\|",name[i])) return -1;
    /* Reject DOS aliases even though the single-leaf NT open avoids DOS parsing. */
    size_t stem=0; while(stem<length && name[stem]!=L'.') ++stem;
    WCHAR upper[8]={0};
    if(stem<sizeof upper/sizeof *upper) {
        for(size_t i=0;i<stem;++i) upper[i]=name[i]>=L'a' && name[i]<=L'z' ? name[i]-L'a'+L'A' : name[i];
        if(!wcscmp(upper,L"CON") || !wcscmp(upper,L"PRN") || !wcscmp(upper,L"AUX")
           || !wcscmp(upper,L"NUL") || !wcscmp(upper,L"CONIN$") || !wcscmp(upper,L"CONOUT$")) return -1;
        if(stem==4 && (!wcsncmp(upper,L"COM",3) || !wcsncmp(upper,L"LPT",3))
           && ((upper[3]>=L'0' && upper[3]<=L'9') || upper[3]==0x00b9 || upper[3]==0x00b2 || upper[3]==0x00b3)) return -1;
    }
    return 0;
}
static inline HANDLE qpc_file_relative(HANDLE parent, WCHAR *name, size_t length,
                                      ACCESS_MASK access, int directory, int create,
                                      PSECURITY_DESCRIPTOR security) {
    if(qpc_file_leaf(name,length)) { SetLastError(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    UNICODE_STRING text={(USHORT)(length*sizeof(WCHAR)),(USHORT)(length*sizeof(WCHAR)),name};
    OBJECT_ATTRIBUTES attributes={sizeof attributes,parent,&text,OBJ_CASE_INSENSITIVE,security,NULL};
    IO_STATUS_BLOCK completion={0}; HANDLE result=NULL;
    NTSTATUS status=NtCreateFile(&result,access|SYNCHRONIZE,&attributes,&completion,NULL,FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,create ? FILE_CREATE : FILE_OPEN,
        (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE)|FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
    if(status!=0 || completion.Status!=0 || !result) {
        DWORD error=RtlNtStatusToDosError(status!=0 ? status : completion.Status);
        if(result) { if(!CloseHandle(result)) error=GetLastError(); }
        SetLastError(error ? error : ERROR_INVALID_HANDLE); return INVALID_HANDLE_VALUE;
    }
    return result;
}
static inline HANDLE qpc_file_directory(const char *path) {
    size_t bytes=strlen(path);
    if(!bytes || bytes>32766) return INVALID_HANDLE_VALUE;
    int length=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,(int)bytes,NULL,0);
    if(length<=0) return INVALID_HANDLE_VALUE;
    WCHAR *wide=malloc(((size_t)length+1)*sizeof *wide);
    if(!wide) return INVALID_HANDLE_VALUE;
    if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,(int)bytes,wide,length)!=length) { free(wide); return INVALID_HANDLE_VALUE; }
    wide[length]=0;
    size_t first=length>=4 && !wcsncmp(wide,L"\\\\?\\",4) ? 4 : 0;
    HANDLE directory=INVALID_HANDLE_VALUE;
    if((size_t)length<first+4 || !((wide[first]>=L'A' && wide[first]<=L'Z') || (wide[first]>=L'a' && wide[first]<=L'z'))
       || wide[first+1]!=L':' || (wide[first+2]!=L'\\' && wide[first+2]!=L'/')) goto done;
    WCHAR root[]={wide[first],L':',L'\\',0};
    UINT drive=GetDriveTypeW(root);
    if(drive!=DRIVE_FIXED && drive!=DRIVE_REMOVABLE && drive!=DRIVE_RAMDISK) goto done;
    directory=CreateFileW(root,FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    if(directory==INVALID_HANDLE_VALUE) goto done;
    WCHAR filesystem[64]; DWORD flags=0; BY_HANDLE_FILE_INFORMATION info;
    if(qpc_file_information(directory,1,&info)
       || !GetVolumeInformationByHandleW(directory,NULL,0,NULL,NULL,&flags,filesystem,64)
       || wcscmp(filesystem,L"NTFS") || !(flags&FILE_PERSISTENT_ACLS)) goto failed;
    for(size_t start=first+3;start<(size_t)length;) {
        size_t end=start; while(end<(size_t)length && wide[end]!=L'\\' && wide[end]!=L'/') ++end;
        int last=end==(size_t)length;
        HANDLE child=qpc_file_relative(directory,wide+start,end-start,
            last ? GENERIC_READ|GENERIC_WRITE : FILE_TRAVERSE|FILE_READ_ATTRIBUTES,1,0,NULL);
        int closed=CloseHandle(directory)!=0; directory=child;
        if(child==INVALID_HANDLE_VALUE) goto done;
        if(!closed || qpc_file_information(child,1,&info)) goto failed;
        if(last) {
            if(qpc_file_private(directory)) goto failed;
            goto done;
        }
        start=end+1;
    }
failed:
    if(directory!=INVALID_HANDLE_VALUE) (void)CloseHandle(directory);
    directory=INVALID_HANDLE_VALUE;
done:
    free(wide); return directory;
}
static inline HANDLE qpc_file_create(HANDLE directory, WCHAR *name, size_t length) {
    struct qpc_file_user user;
    union { ACL alignment; unsigned char bytes[sizeof(ACL)+sizeof(ACCESS_ALLOWED_ACE)+SECURITY_MAX_SID_SIZE]; } storage;
    PACL acl=(PACL)storage.bytes; SECURITY_DESCRIPTOR descriptor;
    if(qpc_file_current_user(&user) || !InitializeAcl(acl,sizeof storage.bytes,ACL_REVISION)
       || !AddAccessAllowedAceEx(acl,ACL_REVISION,0,FILE_ALL_ACCESS,user.sid)
       || !InitializeSecurityDescriptor(&descriptor,SECURITY_DESCRIPTOR_REVISION)
       || !SetSecurityDescriptorOwner(&descriptor,user.sid,FALSE)
       || !SetSecurityDescriptorDacl(&descriptor,TRUE,acl,FALSE)
       || !SetSecurityDescriptorControl(&descriptor,SE_DACL_PROTECTED,SE_DACL_PROTECTED)) return INVALID_HANDLE_VALUE;
    return qpc_file_relative(directory,name,length,GENERIC_READ|GENERIC_WRITE|DELETE,0,1,&descriptor);
}
static inline int qpc_file_existing(HANDLE directory, WCHAR *name, const uint8_t *bytes, size_t length) {
    HANDLE file=qpc_file_relative(directory,name,wcslen(name),GENERIC_READ|GENERIC_WRITE,0,0,NULL);
    if(file==INVALID_HANDLE_VALUE) return GetLastError()==ERROR_FILE_NOT_FOUND ? 1 : -1;
    BY_HANDLE_FILE_INFORMATION info; uint8_t observed[4096]; size_t used=0;
    int bad=qpc_file_information(file,0,&info) || qpc_file_private(file)
        || info.nFileSizeHigh || info.nFileSizeLow!=length;
    while(!bad && used<length) {
        DWORD count=0, wanted=(DWORD)(length-used>sizeof observed ? sizeof observed : length-used);
        if(!ReadFile(file,observed,wanted,&count,NULL) || !count || count>wanted || memcmp(observed,bytes+used,count)) bad=1;
        else used+=count;
    }
    DWORD extra=0;
    if(!bad && (!ReadFile(file,observed,1,&extra,NULL) || extra || !FlushFileBuffers(file))) bad=1;
    if(!CloseHandle(file)) bad=1;
    if(!bad && (qpc_file_private(directory) || !FlushFileBuffers(directory))) bad=1;
    return bad ? -1 : 0;
}
static inline int qpc_file_publish(HANDLE file, HANDLE directory, WCHAR *name) {
    size_t length=wcslen(name);
    if(qpc_file_leaf(name,length)) return -1;
    size_t size=offsetof(FILE_RENAME_INFO,FileName)+(length+1)*sizeof(WCHAR);
    FILE_RENAME_INFO *rename=calloc(1,size);
    if(!rename) return -1;
    rename->ReplaceIfExists=FALSE; rename->RootDirectory=directory;
    rename->FileNameLength=(DWORD)(length*sizeof(WCHAR));
    memcpy(rename->FileName,name,(length+1)*sizeof(WCHAR));
    BOOL ok=SetFileInformationByHandle(file,FileRenameInfo,rename,(DWORD)size);
    DWORD error=ok ? ERROR_SUCCESS : GetLastError(); free(rename);
    SetLastError(error);
    return ok ? 0 : (error==ERROR_FILE_EXISTS || error==ERROR_ALREADY_EXISTS ? 1 : -1);
}
/* Failure stages belong to this private application helper, not the SDK ABI.
 * They keep a native failure distinguishable from input/record admission. */
enum qpc_file_failure {
    QPC_FILE_DIRECTORY=-2, QPC_FILE_ORIGINAL=-3, QPC_FILE_STAGING=-4,
    QPC_FILE_SHAPE=-5, QPC_FILE_WRITE=-6, QPC_FILE_FLUSH=-7,
    QPC_FILE_PUBLICATION=-8, QPC_FILE_DISPOSAL=-9, QPC_FILE_CLOSE=-10,
    QPC_FILE_READBACK=-11, QPC_FILE_PARENT_CLOSE=-12
};
static inline int qpc_file_commit(const char *path, const char *name, const uint8_t *bytes, size_t length, int *created) {
    *created=0;
    if(!length || length>1048576) return -1;
    WCHAR final[256],temporary[256];
    int width=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,-1,final,256);
    if(width<=0 || qpc_file_leaf(final,(size_t)width-1)) return -1;
    int count=swprintf(temporary,256,L".%ls.%lu.tmp",final,(unsigned long)GetCurrentProcessId());
    if(count<0 || count>=256) return -1;
    HANDLE directory=qpc_file_directory(path);
    if(directory==INVALID_HANDLE_VALUE) return QPC_FILE_DIRECTORY;
    int found=qpc_file_existing(directory,final,bytes,length);
    if(found!=1) { if(!CloseHandle(directory)) return QPC_FILE_PARENT_CLOSE; return found ? QPC_FILE_ORIGINAL : 0; }
    HANDLE file=qpc_file_create(directory,temporary,(size_t)count);
    if(file==INVALID_HANDLE_VALUE) {
        DWORD error=GetLastError(); (void)CloseHandle(directory); SetLastError(error);
        return QPC_FILE_STAGING;
    }
    BY_HANDLE_FILE_INFORMATION info;
    int bad=(qpc_file_information(file,0,&info) || qpc_file_private(file)) ? QPC_FILE_SHAPE : 0;
    size_t used=0;
    while(!bad && used<length) {
        DWORD written=0;
        if(!WriteFile(file,bytes+used,(DWORD)(length-used),&written,NULL) || !written || written>length-used) bad=QPC_FILE_WRITE;
        else used+=written;
    }
    if(!bad && (!FlushFileBuffers(file) || qpc_file_private(directory))) bad=QPC_FILE_FLUSH;
    if(!bad) {
        int published=qpc_file_publish(file,directory,final);
        if(published==0) *created=1;
        else if(published<0) bad=QPC_FILE_PUBLICATION;
    }
    DWORD original_error=GetLastError();
    if(!*created) {
        FILE_DISPOSITION_INFO disposition={TRUE};
        if(!SetFileInformationByHandle(file,FileDispositionInfo,&disposition,sizeof disposition) && !bad) {
            bad=QPC_FILE_DISPOSAL; original_error=GetLastError();
        }
    }
    if(!CloseHandle(file) && !bad) { bad=QPC_FILE_CLOSE; original_error=GetLastError(); }
    if(!bad && qpc_file_existing(directory,final,bytes,length)!=0) { bad=QPC_FILE_READBACK; original_error=GetLastError(); }
    if(!CloseHandle(directory) && !bad) { bad=QPC_FILE_PARENT_CLOSE; original_error=GetLastError(); }
    if(bad) SetLastError(original_error);
    return bad;
}
#endif
