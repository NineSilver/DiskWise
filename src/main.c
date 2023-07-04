#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int verb_flag = 0, force_flag = 0, print_flag = 0, part = 1;
static char *mbr_file, *vbr_file;

static const char* partition_type_to_text[] = {
    [0x00] = "Empty",
    [0x01] = "FAT12",
    [0x02] = "XENIX root",
    [0x03] = "XENIX usr",
    [0x04] = "FAT16 <32M",
    [0x05] = "Extended Partition",
    [0x06] = "FAT16",
    [0x07] = "HPFS/NTFS/exFAT",
    [0x08] = "AIX",
    [0x09] = "AIX bootable",
    [0x0a] = "OS/2 Boot Manager",
    [0x0b] = "WIN95 FAT32",
    [0x0c] = "WIN95 FAT32 (LBA)",
    [0x0d] = "Unused",
    [0x0e] = "WIN95 FAT16 (LBA)",
    [0x0f] = "WIN95 Extended partition (LBA)",
    [0x10] = "OPUS",
    [0x11] = "Hidden FAT12",
    [0x12] = "Compaq diagnostic partition",
    [0x13] = "Unused",
    [0x14] = "Hidden FAT16 <32M",
    [0x15] = "Unused",
    [0x16] = "Hidden FAT16",
    [0x17] = "Hidden HPFS/NTFS",
    [0x18] = "AST SmartSleep Partition",
    [0x19] = "Unused",
    [0x1a] = "Unused",
    [0x1b] = "Hidden WIN95 FAT32",
    [0x1c] = "Hidden WIN95 FAT32 (LBA)",
    [0x1d] = "Unused",
    [0x1e] = "Hidden WIN95 FAT16 (LBA)",
    [0x20] = "Unused",
    [0x21] = "Reserved",
    [0x22] = "Unused",
    [0x23] = "Reserved",
    [0x24] = "NEC DOS",
    [0x25] = "Unused",
    [0x26] = "Reserved",
    [0x27] = "Hidden NTFS",
    [0x28] = "Unused",
    [0x29] = "Unused",
    [0x2a] = "Unused",
    [0x2b] = "Unused",
    [0x2c] = "Unused",
    [0x2d] = "Unused",
    [0x2e] = "Unused",
    [0x2f] = "Unused",
    [0x30] = "Unused",
    [0x31] = "Reserved",
    [0x32] = "NOS",
    [0x33] = "Reserved",
    [0x34] = "Reserved",
    [0x35] = "JFS",
    [0x36] = "Reserved",
    [0x37] = "Unused",
    [0x38] = "THEOS 3.2 2GB",
    [0x39] = "Plan 9 partition",
    [0x3a] = "THEOS 4 4GB",
    [0x3b] = "THEOS 4 extended partition",
    [0x3c] = "PartitionMagic recovery",
    [0x3d] = "Hidden NetWare",
    [0x3e] = "Unused",
    [0x3f] = "Unused",
    [0x40] = "Venix 80286",
    [0x41] = "PPC PReP Boot",
    [0x42] = "SFS",
    [0x43] = "Unused",
    [0x44] = "GoBack partition",
    [0x45] = "Boot-US boot manager",
    [0x46] = "EUMEL/Elan",
    [0x47] = "EUMEL/Elan",
    [0x48] = "EUMEL/Elan",
    [0x4a] = "AdaOS Aquila",
    [0x4b] = "Unused",
    [0x4c] = "Oberon partition",
    [0x4d] = "QNX4",
    [0x4e] = "QNX4 2nd part",
    [0x4f] = "QNX4 3rd part",
    [0x50] = "OnTrack Disk Manager",
    [0x51] = "OnTrack Disk Manager 6 Aux",
    [0x52] = "CP/M",
    [0x53] = "OnTrack Disk Manager 6 Aux",
    [0x54] = "OnTrack Disk Manager 6 DDO",
    [0x55] = "EZ-Drive",
    [0x56] = "Golden Bow",
    [0x57] = "DrivePro",
    [0x58] = "Unused",
    [0x59] = "Unused",
    [0x5a] = "Unused",
    [0x5b] = "Unused",
    [0x5c] = "Priam EDisk",
    [0x5d] = "Unused",
    [0x5e] = "Unused",
    [0x5f] = "Unused",
    [0x60] = "Unused",
    [0x61] = "SpeedStor",
    [0x62] = "Unused",
    [0x63] = "Unix SysV / HURD",
    [0x64] = "Novell Netware 2",
    [0x65] = "Novell Netware 3/4",
    [0x66] = "Novell Netware SMS",
    [0x67] = "Novell",
    [0x68] = "Novell",
    [0x69] = "Novell Netware 5+ / Netware NSS",
    [0x70] = "DiskSecure Multi-Boot",
    [0x71] = "Reserved",
    [0x72] = "Unused",
    [0x73] = "Reserved",
    [0x74] = "Reserved",
    [0x75] = "IBM PC/IX",
    [0x76] = "Reserved",
    [0x77] = "M2FS/M2CS partition",
    [0x78] = "XOSL FS",
    [0x79] = "Unused",
    [0x7a] = "Unused",
    [0x7b] = "Unused",
    [0x7c] = "Unused",
    [0x7d] = "Unused",
    [0x7e] = "Unknown",
    [0x7f] = "Unused",
    [0x80] = "Old MINIX",
    [0x81] = "MINIX / old Linux",
    [0x82] = "Linux swap",
    [0x83] = "Linux native",
    [0x84] = "OS/2 hidden",
    [0x85] = "Linux extended partition",
    [0x86] = "NTFS volume set",
    [0x87] = "NTFS volume set",
    [0x88] = "Linux plaintext",
    [0x89] = "Unused",
    [0x8a] = "Linux kernel partition (AiR-BOOT)",
    [0x8b] = "Legacy Fault Tolerant FAT32",
    [0x8c] = "Legacy Fault Tolerant FAT32 (extended)",
    [0x8d] = "Free FDISK hidden FAT12",
    [0x8e] = "Linux LVM",
    [0x8f] = "Unused",
    [0x90] = "Free FDISK hidden FAT16",
    [0x91] = "Free FDISK hidden DOS extended partitition",
    [0x92] = "Free FDISK hidden large FAT16",
    [0x93] = "Amoeba",
    [0x94] = "Amoeba BBT",
    [0x95] = "MIT EXOPC native",
    [0x97] = "Free FDISK hidden FAT32",
    [0x98] = "Free FDISK hidden FAT32 (LBA)",
    [0x99] = "DCE376 logical drive",
    [0x9a] = "Free FDISK hidden FAT16 (LBA)",
    [0x9b] = "Free FDISK hidden DOS extended partitition (LBA)",
    [0x9c] = "Unused",
    [0x9d] = "Unused",
    [0x9e] = "Unused",
    [0x9f] = "BSD/OS",
    [0xa0] = "Thinkpad hibernation",
    [0xa1] = "Laptop hibernation partition",
    [0xa2] = "Unused",
    [0xa3] = "Reserved",
    [0xa4] = "Reserved",
    [0xa5] = "FreeBSD",
    [0xa6] = "OpenBSD",
    [0xa7] = "NeXTSTEP",
    [0xa8] = "Darwin UFS",
    [0xa9] = "NetBSD",
    [0xaa] = "Olivetti FAT12",
    [0xab] = "Darwin boot",
    [0xac] = "Unused",
    [0xad] = "Unused",
    [0xae] = "ShagOS filesystem",
    [0xaf] = "HFS / HFS+",
    [0xb0] = "BootStar Dummy",
    [0xb1] = "Reserved",
    [0xb2] = "Unused",
    [0xb3] = "Reserved",
    [0xb4] = "Reserved",
    [0xb6] = "Reserved",
    [0xb7] = "BSDI filesystem",
    [0xb8] = "BSDI swap",
    [0xb9] = "Unused",
    [0xba] = "Unused",
    [0xbb] = "Boot Wizard hidden",
    [0xbc] = "Acronis FAT32 LBA",
    [0xbd] = "Unused",
    [0xbe] = "Solaris boot partition",
    [0xbf] = "Solaris",
    [0xc0] = "CTOS",
    [0xc1] = "DRDOS secured (FAT12)",
    [0xc2] = "Hidden Linux",
    [0xc3] = "Hidden Linux swap",
    [0xc4] = "DRDOS secured (FAT16 < 32M)",
    [0xc5] = "DRDOS secured (extended)",
    [0xc6] = "DRDOS secured (FAT16)",
    [0xc7] = "Syrinx boot",
    [0xc8] = "Unknown",
    [0xc9] = "Unknown",
    [0xca] = "Unknown",
    [0xcb] = "Reserved for DRDOS secured (FAT32)",
    [0xcc] = "Reserved for DRDOS secured (FAT32 LBA)",
    [0xcd] = "Unknown",
    [0xce] = "reserved for DRDOS secured (FAT16 LBA)",
    [0xcf] = "Unused",
    [0xd0] = "REAL/32 secure",
    [0xd1] = "Old Multiuser DOS secured FAT12",
    [0xd2] = "Unused",
    [0xd3] = "Unused",
    [0xd4] = "Old Multiuser DOS secured FAT16 <32M",
    [0xd5] = "Old Multiuser DOS secured extended",
    [0xd6] = "Old Multiuser DOS secured FAT16",
    [0xd7] = "Unused",
    [0xd8] = "CP/M-86",
    [0xd9] = "Unused",
    [0xda] = "Non-FS Data",
    [0xdb] = "CP/M / CTOS / KDG SCPU",
    [0xdc] = "Unused",
    [0xdd] = "Unknown",
    [0xde] = "Dell PowerEdge (FAT)",
    [0xdf] = "BootIt EMBRM / DG/UX disk manager",
    [0xe0] = "Reserved",
    [0xe1] = "DOS access / SpeedStor FAT12 extended",
    [0xe2] = "Unused",
    [0xe3] = "DOS RO / SpeedStor",
    [0xe4] = "SpeedStor FAT16 extended partition",
    [0xe5] = "Reserved",
    [0xe6] = "Reserved",
    [0xe7] = "Unused",
    [0xe8] = "Unused",
    [0xe9] = "Unused",
    [0xea] = "Linux extended",
    [0xeb] = "BeFS",
    [0xec] = "Unused",
    [0xed] = "Reserved",
    [0xee] = "GPT partitioned disk",
    [0xef] = "EFI File System",
    [0xf0] = "Linux/PA-RISC boot loader",
    [0xf1] = "SpeedStor",
    [0xf2] = "DOS secondary partition",
    [0xf3] = "Reserved",
    [0xf4] = "SpeedStor large partition",
    [0xf5] = "Prologue multi-volume partition",
    [0xf6] = "Reserved",
    [0xf7] = "Unused",
    [0xf8] = "EBBR Protective",
    [0xf9] = "Unused",
    [0xfa] = "Bochs",
    [0xfb] = "VMware File System",
    [0xfc] = "VMware Swap",
    [0xfd] = "Linux RAID autodetect",
    [0xfe] = "LANstep",
    [0xff] = "Xenix BBT",
};

struct partition_record
{
    uint8_t attributes;
    uint8_t start_chs[3];
    uint8_t type;
    uint8_t end_chs[3];
    uint32_t lba_start;
    uint32_t sector_num;
} __attribute__((packed));

struct mbr
{
    uint8_t bootcode[440];
    uint32_t disk_uid;
    uint16_t reserved;
    struct partition_record partitions[4];
    uint16_t signature;
} __attribute__((packed));

char* strdup(const char* s);

static int status_log(const char* format, ...)
{
    int ret = 0;

    if(verb_flag)
    {
        va_list args;
        va_start(args, format);
        ret = vprintf(format, args);
        va_end(args);
    }

    return ret;
}

static void help(char* progname)
{
    fprintf(stderr, "Usage: %s [-vf] OPTIONS IMAGE\n", progname);
    fprintf(stderr, "Modify the MBR and VBRs of a given image.\n\n");
    fprintf(stderr, "     --print\t\tprint the MBR details\n");
    fprintf(stderr, " -m, --mbr FILE\t\twrite FILE to MBR\n");
    fprintf(stderr, " -v, --vbr FILE\t\twrite FILE to VBR\n");
    fprintf(stderr, " -p, --part NUM\t\tspecify the partition to modify\n");
    fprintf(stderr, " -f, --force\t\tforce the write of the entire sector\n");
    fprintf(stderr, "     --verbose\t\texplain every step that is done\n\n");
    fprintf(stderr, " -h, --help\t\tdisplay this help and exit\n\n");
    fprintf(stderr,
            "By default, the selected partition is 1. Files passed to "
            "--mbr and --vbr will be truncated to the first 512 bytes.\n");
    fprintf(stderr, "--print and --mbr (--vbr) are mutually exclusive.\n\n");
}

static void dump_mbr(int fd)
{
    struct mbr* mbr =
        mmap(NULL, sizeof(struct mbr), PROT_WRITE, MAP_SHARED, fd, 0);
    if(mbr == MAP_FAILED)
    {
        fprintf(stderr, "ERROR mmap'ing the image (%s)\n", strerror(errno));
        return;
    }

    printf("Master Boot Record\n");
    printf(" - Disk UID: 0x%08x\n", mbr->disk_uid);
    printf(" - Reserved: %s\n",
           mbr->reserved == 0x5a5a ? "read-only" : "unset");
    printf(" - Signature: 0x%04x (%s)\n", mbr->signature,
           mbr->signature == 0xaa55 ? "valid" : "invalid");

    for(int i = 0; i < 4; i++)
    {

        printf("\nPartition #%i:\n", i + 1);
        printf(" - Attributes: 0x02%x (%s)\n", mbr->partitions[i].attributes,
               mbr->partitions[i].attributes & (1 << 7) ? "active"
                                                        : "not bootable");
        uint16_t cylinder =
            (((uint16_t)(mbr->partitions[i].start_chs[2]) << 2) |
             ((uint16_t)(mbr->partitions[i].start_chs[1]) >> 6));
        uint8_t head = mbr->partitions[i].start_chs[0];
        uint8_t sector = (mbr->partitions[i].start_chs[1] & 0x3F);
        printf(" - Start CHS: %u %u %u\n", cylinder, head, sector);
        printf(" - Partition type: 0x%02x (%s)\n", mbr->partitions[i].type,
               partition_type_to_text[mbr->partitions[i].type]);

        cylinder = (((uint16_t)(mbr->partitions[i].end_chs[2]) << 2) |
                    ((uint16_t)(mbr->partitions[i].end_chs[1]) >> 6));
        head = mbr->partitions[i].end_chs[0];
        sector = (mbr->partitions[i].end_chs[1] & 0x3F);
        printf(" - End CHS: %u %u %u\n", cylinder, head, sector);
        printf(" - Start LBA: %u\n", mbr->partitions[i].lba_start);
        printf(" - Number of sectors: %u\n", mbr->partitions[i].sector_num);
    }

    munmap(mbr, sizeof(struct mbr));
}

static void write_boot_records(int image_fd)
{
    size_t bytes;
    if(mbr_file)
    {
        status_log("INFO: opening source MBR %s\n", mbr_file);
        int mbr_fd = open(mbr_file, O_RDONLY);
        void* mbr = malloc(sizeof(struct mbr));
        bytes = read(mbr_fd, mbr, sizeof(struct mbr));
        if(bytes != sizeof(struct mbr))
        {
            fprintf(stderr, "ERROR reading source MBR (%s)\n", strerror(errno));
            return;
        }
        lseek(image_fd, 0, SEEK_SET);

        if(force_flag)
        {
            status_log("INFO: writing the whole MBR (--force)\n");
            bytes = write(image_fd, mbr, sizeof(struct mbr));
            if(bytes != sizeof(struct mbr))
            {
                fprintf(stderr, "ERROR writing MBR to image (%s)\n", strerror(errno));
                return;
            }
        }
        else
        {
            status_log("INFO: writing the first 446 bytes of MBR (boot code)\n");
            bytes = write(image_fd, mbr, 446);
            if(bytes != 446)
            {
                fprintf(stderr, "ERROR writing MBR to image (%s)\n", strerror(errno));
                return;
            }
            lseek(image_fd, 446, SEEK_CUR);
            status_log("INFO: writing the last 2 bytes of MBR (signature)\n");
            bytes = write(image_fd, mbr + 446, 2);
            if(bytes != 2)
            {
                fprintf(stderr, "ERROR writing MBR to image (%s)\n", strerror(errno));
                return;
            }
        }

        close(mbr_fd);
        free(mbr);
    }

    if(vbr_file)
    {
        status_log("INFO: opening source VBR %s\n", vbr_file);
        lseek(image_fd,
              446 + ((part - 1) * sizeof(struct partition_record)) + 8,
              SEEK_SET);
        uint32_t lba;
        bytes = read(image_fd, &lba, 4);
        if(bytes != 4)
        {
            fprintf(stderr, "ERROR computing VBR location (%s)\n", strerror(errno));
            return;
        }
        status_log("INFO: VBR will be written to partition %d (LBA %u)\n", part, lba);

        int vbr_fd = open(vbr_file, O_RDONLY);
        void* vbr = malloc(512);
        bytes = read(vbr_fd, vbr, 512);
        if(bytes != 512)
        {
            fprintf(stderr, "ERROR reading source VBR (%s)\n", strerror(errno));
            return;
        }
        lseek(image_fd, lba * 512, SEEK_SET);

        if(force_flag)
        {
            status_log("INFO: writing the whole VBR (--force)\n");
            bytes = write(image_fd, vbr, 512);
            if(bytes != 512)
            {
                fprintf(stderr, "ERROR writing VBR to image (%s)\n", strerror(errno));
                return;
            }
        }
        else
        {
            status_log("INFO: writing the first 3 bytes of VBR (jump)\n");
            bytes = write(image_fd, vbr, 3);
            if(bytes != 3)
            {
                fprintf(stderr, "ERROR writing VBR to image (%s)\n", strerror(errno));
                return;
            }
            lseek(image_fd, 90, SEEK_CUR);
            status_log("INFO: writing the last 422 bytes of VBR (boot code)\n");
            bytes = write(image_fd, vbr + 90, 422);
            if(bytes != 422)
            {
                fprintf(stderr, "ERROR writing VBR to image (%s)\n", strerror(errno));
                return;
            }
        }

        close(vbr_fd);
        free(vbr);
    }
}

int main(int argc, char* argv[])
{
    int c;

    for(;;)
    {
        static struct option opts[] = {
            {"help", no_argument, NULL, 'h'},
            {"verbose", no_argument, &verb_flag, 1},
            {"force", no_argument, &force_flag, 1},

            {"print", no_argument, &print_flag, 1},
            {"mbr", required_argument, NULL, 'm'},
            {"vbr", required_argument, NULL, 'v'},
            {"part", required_argument, NULL, 'p'},
            {0, 0, 0, 0},
        };

        int option_index = 0;
        c = getopt_long(argc, argv, "hfm:v:p:", opts, &option_index);
        if(c == -1) break;
        switch(c)
        {
            case 0:
                break;

            case 'h':
                help(argv[0]);
                return 0;

            case 'f':
                force_flag = 1;
                break;

            case 'm':
                mbr_file = strdup(optarg);
                break;

            case 'v':
                vbr_file = strdup(optarg);
                break;

            case 'p':
                if((part = atoi(optarg)) == 0)
                {
                    fprintf(stderr, "ERROR: option -p expects a number "
                                    "between 1 and 4.\n");
                    return 1;
                }

                printf("%u\n", part);
                break;

            case '?':
            default:
                return 1;
        }
    }

    if(optind >= argc)
    {
        fprintf(stderr, "%s: missing image operand\n", argv[0]);
        return 1;
    }

    char* image_path = argv[optind];
    if(part < 1 || part > 4)
    {
        fprintf(stderr, "Warning: invalid partition index. Defaulting to 1.\n");
        part = 1;
    }

    int fd;
    if((fd = open(image_path, O_RDWR)) == -1)
    {
        fprintf(stderr, "ERROR: unable to open %s (%s)\n", image_path,
                strerror(errno));
        return 1;
    }

    if(print_flag)
    {
        dump_mbr(fd);
    }
    else
    {
        write_boot_records(fd);
    }

    close(fd);
    return 0;
}