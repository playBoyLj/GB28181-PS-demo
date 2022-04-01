#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
 
#define PS_HDR_LEN  14
#define SYS_HDR_LEN 18
#define PSM_HDR_LEN 24
#define PES_HDR_LEN 19
#define RTP_HDR_LEN 12
#define RTP_VERSION 2
#define RTP_MAX_PACKET_BUFF 1460
#define PS_PES_PAYLOAD_SIZE 65522
#define AND8BIT(X) (0XFF >> (8 -X))
/*	H264定义的类型 values for nal_unit_type	*/
typedef enum 
{
  NALU_TYPE_SLICE    = 1,		//	P帧				(非IDR图像的编码条带(Coded slice of a non-IDR picture))
  NALU_TYPE_DPA      = 2,		//					(编码条带数据分割块A (Coded slice data partition A))
  NALU_TYPE_DPB      = 3,		//					(编码条带数据分割块B (Coded slice data partition B))
  NALU_TYPE_DPC      = 4,		//					(编码条带数据分割块C (Coded slice data partition C))
  NALU_TYPE_IDR      = 5,		//	IDR帧			(IDR图像的编码条带(Coded slice of an IDR picture))
  NALU_TYPE_SEI      = 6,		//  SEI				(辅助增强信息 Supplemental enhancement information(SEI))
  NALU_TYPE_SPS      = 7,		//	SPS关键帧		(序列参数集 Sequence parameter set)
  NALU_TYPE_PPS      = 8,		//	PPS关键帧		(图像参数集 Picture parameter set)
  NALU_TYPE_AUD      = 9,		//	AUD				(访问单元分隔符 Access Unit Delimiter)
  NALU_TYPE_EOSEQ    = 10,	//					(序列结尾 End of sequence)
  NALU_TYPE_EOSTREAM = 11,	//					(流结尾 End of stream)
  NALU_TYPE_FILL     = 12,	//					(填充数据 Filler data)

} NAL_UNIT_TYPE;
union LESize
{
  unsigned short int  length;
  unsigned char   byte[2];
};
 
 typedef struct{
  unsigned char* p_data;
  unsigned char  i_mask;
  int i_size;
  int i_data;
}bits_buffer_s;
 
 typedef struct{
  uint64_t s64CurPts;
  int      IFrame;
  uint16_t u16CSeq;
  uint32_t u32Ssrc;
  char szBuff[RTP_MAX_PACKET_BUFF];
}Data_Info_s;
 
int _socketFd;
/***
 *@remark:  讲传入的数据按地位一个一个的压入数据
 *@param :  buffer   [in]  压入数据的buffer
 *          count    [in]  需要压入数据占的位数
 *          bits     [in]  压入的数值
 */
#define bits_write(buffer, count, bits)\
{\
  bits_buffer_s *p_buffer = (buffer);\
  int i_count = (count);\
  uint64_t i_bits = (bits);\
  while( i_count > 0 )\
  {\
    i_count--;\
    if( ( i_bits >> i_count )&0x01 )\
    {\
      p_buffer->p_data[p_buffer->i_data] |= p_buffer->i_mask;\
    }\
    else\
    {\
      p_buffer->p_data[p_buffer->i_data] &= ~p_buffer->i_mask;\
    }\
    p_buffer->i_mask >>= 1;         /*操作完一个字节第一位后，操作第二位*/\
    if( p_buffer->i_mask == 0 )     /*循环完一个字节的8位后，重新开始下一位*/\
    {\
      p_buffer->i_data++;\
      p_buffer->i_mask = 0x80;\
    }\
  }\
}
int gb28181_make_pes_header(char *pData, int stream_id, int payload_len, unsigned long long pts, unsigned long long dts);
int gb28181_make_psm_header(char *pData);
int gb28181_make_sys_header(char *pData);
int gb28181_make_ps_header(char *pData, unsigned long long s64Scr);
int findStartCode(unsigned char *buf, int zeros_in_startcode)
{
    int info;
    int i;
 
    info = 1;
    for (i = 0; i < zeros_in_startcode; i++)
        if (buf[i] != 0)
            info = 0;
 
    if (buf[i] != 1)
        info = 0;
    return info;
}
int getNextNalu(FILE* inpf, unsigned char* buf, Data_Info_s* pPacker)
{
    int pos = 0;
    int startCodeFound = 0;
    int info2 = 0;
    int info3 = 0;
    unsigned char NAL_UNIT;
    pPacker->IFrame = 0;
    while (!feof(inpf) && (buf[pos++] = fgetc(inpf)) == 0);
 
    while (!startCodeFound)
    {
        if (feof(inpf))
        {
            return pos - 1;
        }
        buf[pos++] = fgetc(inpf);
        info3 = findStartCode(&buf[pos - 4], 3);
        startCodeFound = (info3 == 1);
        if (info3 != 1)
            info2 = findStartCode(&buf[pos - 3], 2);
        startCodeFound = (info2 == 1 || info3 == 1);
    }
        if (buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 1)
    {
      /* code */
      NAL_UNIT = buf[4] & AND8BIT(5);
    }
    if (buf[0] == 0 && buf[1] == 0 && buf[2] == 1)
    {
      /* code */
      NAL_UNIT = buf[3] & AND8BIT(5);
    }   
    if (NAL_UNIT ==  NALU_TYPE_IDR || NAL_UNIT == NALU_TYPE_SPS)
    {
      pPacker->IFrame = 1;
    }
    if (info2)
    {        
        fseek(inpf, -3, SEEK_CUR);
        return pos - 3;
    }
    if (info3)
    {
        fseek(inpf, -4, SEEK_CUR);
        return pos - 4;
    } 
}
/***
 *@remark:  音视频数据的打包成ps流，并封装成rtp
 *@param :  pData      [in] 需要发送的音视频数据
 *          nFrameLen  [in] 发送数据的长度
 *          pPacker    [in] 数据包的一些信息，包括时间戳，rtp数据buff，发送的socket相关信息
 *          stream_type[in] 数据类型 0 视频 1 音频
 *@return:  0 success others failed
*/
 
int gb28181_streampackageForH264(char *pData, int nFrameLen, Data_Info_s* pPacker, int stream_type)
{
  char szTempPacketHead[256];
  int  nSizePos = 0;
  int  nSize = 0;   
  char* pBuff = (char*) malloc(1024*1024);
  char* pBuffmark = pBuff;
  FILE *fp ;
  memset(szTempPacketHead, 0, 256);
  // 1 package for ps header 
  gb28181_make_ps_header(szTempPacketHead + nSizePos, pPacker->s64CurPts);
  nSizePos += PS_HDR_LEN; 
  //2 system header 
  if( pPacker->IFrame == 1 )
  {
    // 如果是I帧的话，则添加系统头
    gb28181_make_sys_header(szTempPacketHead + nSizePos);
    nSizePos += SYS_HDR_LEN;

    gb28181_make_psm_header(szTempPacketHead + nSizePos);
    nSizePos += PSM_HDR_LEN;
 
  }

  if (pPacker->IFrame == 1)
  {
    /* code */
    pBuff += PES_HDR_LEN + PS_HDR_LEN + SYS_HDR_LEN + PSM_HDR_LEN ;
  }
  else
  {
    /* code */
    pBuff += PES_HDR_LEN + PS_HDR_LEN ;
    
  }
  memcpy(pBuff, pData, nFrameLen);
  pBuff = pBuff - PES_HDR_LEN ;
  printf("%d\n",pPacker->IFrame);
  while(nFrameLen > 0)
  {
        //每次帧的长度不要超过short类型，过了就得分片进循环行发送
    nSize = (nFrameLen > PS_PES_PAYLOAD_SIZE) ? PS_PES_PAYLOAD_SIZE : nFrameLen;
        // 添加pes头
    gb28181_make_pes_header(pBuff, stream_type ? 0xC0:0xE0, nSize, pPacker->s64CurPts, pPacker->s64CurPts);
        for (int i= 0; i <pPacker->IFrame ; ++i)
        {
            printf("               %d\n",i);
        }

    if (pPacker->IFrame == 1 )
    {
      /* code */
      pBuff = pBuff - PS_HDR_LEN - SYS_HDR_LEN - PSM_HDR_LEN;
      memcpy(pBuff, szTempPacketHead, PS_HDR_LEN + SYS_HDR_LEN + PSM_HDR_LEN);
    }
    else
    {
      /* code */
       pBuff = pBuff - PS_HDR_LEN;
       memcpy(pBuff, szTempPacketHead, PS_HDR_LEN);
    }
       fp = fopen("stu.zv","ab"); // b:表示以二进制写入
    if (pPacker->IFrame == 1)
    {
      fwrite( (char*)pBuff,sizeof(char),nSize + PES_HDR_LEN + PS_HDR_LEN + SYS_HDR_LEN + PSM_HDR_LEN,fp);
      pBuff  += nSize + PS_HDR_LEN + SYS_HDR_LEN + PSM_HDR_LEN;
    }
    else
    {
      fwrite( (char*)pBuff,sizeof(char),nSize + PES_HDR_LEN + PS_HDR_LEN,fp);
      //这里也只移动nSize,因为在while向后移动的pes头长度，正好重新填充pes头数据
      pBuff  += nSize + PS_HDR_LEN;
    }
    fclose(fp);
    //分片后每次发送的数据移动指针操作
    nFrameLen -= nSize;
  }
  free(pBuffmark);
  return 0;
}

/***
 *@remark:   ps头的封装,里面的具体数据的填写已经占位，可以参考标准
 *@param :   pData  [in] 填充ps头数据的地址
 *           s64Src [in] 时间戳
 *@return:   0 success, others failed
*/
int gb28181_make_ps_header(char *pData, unsigned long long s64Scr)
{
    unsigned long long lScrExt = (s64Scr) % 100;  
    //s64Scr = s64Scr / 100;

    // 这里除以100是由于sdp协议返回的video的频率是90000，帧率是25帧/s，所以每次递增的量是3600,
    // 所以实际你应该根据你自己编码里的时间戳来处理以保证时间戳的增量为3600即可，
    //如果这里不对的话，就可能导致卡顿现象了
    bits_buffer_s   bitsBuffer;
    bitsBuffer.i_size = PS_HDR_LEN; 
    bitsBuffer.i_data = 0;
    bitsBuffer.i_mask = 0x80; // 二进制：10000000 这里是为了后面对一个字节的每一位进行操作，避免大小端夸字节字序错乱
    bitsBuffer.p_data = (unsigned char *)(pData);
    memset(bitsBuffer.p_data, 0, PS_HDR_LEN);
    bits_write(&bitsBuffer, 32, 0x000001BA);      /*start codes*/
    bits_write(&bitsBuffer, 2,  1);           /*marker bits '01b'*/
    bits_write(&bitsBuffer, 3,  (s64Scr>>30)&0x07);     /*System clock [32..30]*/
    bits_write(&bitsBuffer, 1,  1);           /*marker bit*/
    bits_write(&bitsBuffer, 15, (s64Scr>>15)&0x7FFF);   /*System clock [29..15]*/
    bits_write(&bitsBuffer, 1,  1);           /*marker bit*/
    bits_write(&bitsBuffer, 15, s64Scr&0x7fff);         /*System clock [14..0]*/
    bits_write(&bitsBuffer, 1,  1);           /*marker bit*/
    bits_write(&bitsBuffer, 9,  lScrExt&0x01ff);    /*System clock ext*/
    bits_write(&bitsBuffer, 1,  1);           /*marker bit*/
    bits_write(&bitsBuffer, 22, (255)&0x3fffff);    /*bit rate(n units of 50 bytes per second.)*/
    bits_write(&bitsBuffer, 2,  3);           /*marker bits '11'*/
    bits_write(&bitsBuffer, 5,  0x1f);          /*reserved(reserved for future use)*/
    bits_write(&bitsBuffer, 3,  0);           /*stuffing length*/
    return 0;
}

/***
 *@remark:   sys头的封装,里面的具体数据的填写已经占位，可以参考标准
 *@param :   pData  [in] 填充ps头数据的地址
 *@return:   0 success, others failed
*/
int gb28181_make_sys_header(char *pData)
{
  
  bits_buffer_s   bitsBuffer;
  bitsBuffer.i_size = SYS_HDR_LEN;
  bitsBuffer.i_data = 0;
  bitsBuffer.i_mask = 0x80;
  bitsBuffer.p_data = (unsigned char *)(pData);
  memset(bitsBuffer.p_data, 0, SYS_HDR_LEN);
  /*system header*/
	bits_write( &bitsBuffer, 32, 0x000001BB); /*start code*/
  bits_write( &bitsBuffer, 16, SYS_HDR_LEN-6);/*header_length 表示次字节后面的长度，后面的相关头也是次意思*/
  bits_write( &bitsBuffer, 1,  1);            /*marker_bit*/
  bits_write( &bitsBuffer, 22, 50000);    /*rate_bound*/
  bits_write( &bitsBuffer, 1,  1);            /*marker_bit*/
  bits_write( &bitsBuffer, 6,  1);            /*audio_bound*/
  bits_write( &bitsBuffer, 1,  0);            /*fixed_flag */
  bits_write( &bitsBuffer, 1,  1);          /*CSPS_flag */
  bits_write( &bitsBuffer, 1,  1);          /*system_audio_lock_flag*/
  bits_write( &bitsBuffer, 1,  1);          /*system_video_lock_flag*/
  bits_write( &bitsBuffer, 1,  1);          /*marker_bit*/
  bits_write( &bitsBuffer, 5,  1);          /*video_bound*/
  bits_write( &bitsBuffer, 1,  0);          /*dif from mpeg1*/
  bits_write( &bitsBuffer, 7,  0x7F);       /*reserver*/
  /*audio stream bound*/
  bits_write( &bitsBuffer, 8,  0xC0);         /*stream_id*/
  bits_write( &bitsBuffer, 2,  3);          /*marker_bit */
  bits_write( &bitsBuffer, 1,  0);            /*PSTD_buffer_bound_scale*/
  bits_write( &bitsBuffer, 13, 512);          /*PSTD_buffer_size_bound*/
  /*video stream bound*/
  bits_write( &bitsBuffer, 8,  0xE0);         /*stream_id*/
  bits_write( &bitsBuffer, 2,  3);          /*marker_bit */
  bits_write( &bitsBuffer, 1,  1);          /*PSTD_buffer_bound_scale*/
  bits_write( &bitsBuffer, 13, 2048);       /*PSTD_buffer_size_bound*/
  return 0;
}
/***
 *@remark:   psm头的封装,里面的具体数据的填写已经占位，可以参考标准
 *@param :   pData  [in] 填充ps头数据的地址
 *@return:   0 success, others failed
*/
int gb28181_make_psm_header(char *pData)
{
  bits_buffer_s   bitsBuffer;
  bitsBuffer.i_size = PSM_HDR_LEN; 
  bitsBuffer.i_data = 0;
  bitsBuffer.i_mask = 0x80;
  bitsBuffer.p_data = (unsigned char *)(pData);
  memset(bitsBuffer.p_data, 0, PSM_HDR_LEN);
  bits_write(&bitsBuffer, 24,0x000001); /*start code*/
  bits_write(&bitsBuffer, 8, 0xBC);   /*map stream id*/
  bits_write(&bitsBuffer, 16,18);     /*program stream map length*/ 
  bits_write(&bitsBuffer, 1, 1);      /*current next indicator */
  bits_write(&bitsBuffer, 2, 3);      /*reserved*/
  bits_write(&bitsBuffer, 5, 0);      /*program stream map version*/
  bits_write(&bitsBuffer, 7, 0x7F);   /*reserved */
  bits_write(&bitsBuffer, 1, 1);      /*marker bit */
  bits_write(&bitsBuffer, 16,0);      /*programe stream info length*/
  bits_write(&bitsBuffer, 16, 8);     /*elementary stream map length  is*/
  /*audio*/
  bits_write(&bitsBuffer, 8, 0x90);       /*stream_type*/
  bits_write(&bitsBuffer, 8, 0xC0);   /*elementary_stream_id*/
  bits_write(&bitsBuffer, 16, 0);     /*elementary_stream_info_length is*/
  /*video*/
  bits_write(&bitsBuffer, 8, 0x1B);       /*stream_type*/
  bits_write(&bitsBuffer, 8, 0xE0);   /*elementary_stream_id*/
  bits_write(&bitsBuffer, 16, 0);     /*elementary_stream_info_length */
  /*crc (2e b9 0f 3d)*/
  bits_write(&bitsBuffer, 8, 0x45);   /*crc (24~31) bits*/
  bits_write(&bitsBuffer, 8, 0xBD);   /*crc (16~23) bits*/
  bits_write(&bitsBuffer, 8, 0xDC);   /*crc (8~15) bits*/
  bits_write(&bitsBuffer, 8, 0xF4);   /*crc (0~7) bits*/
  return 0;
}
/***
 *@remark:   pes头的封装,里面的具体数据的填写已经占位，可以参考标准
 *@param :   pData      [in] 填充ps头数据的地址
 *           stream_id  [in] 码流类型
 *           paylaod_len[in] 负载长度
 *           pts        [in] 时间戳
 *           dts        [in]
 *@return:   0 success, others failed
*/
int gb28181_make_pes_header(char *pData, int stream_id, int payload_len, unsigned long long pts, unsigned long long dts)
{
  bits_buffer_s   bitsBuffer;
  bitsBuffer.i_size = PES_HDR_LEN;
  bitsBuffer.i_data = 0;
  bitsBuffer.i_mask = 0x80;
  bitsBuffer.p_data = (unsigned char *)(pData);
  memset(bitsBuffer.p_data, 0, PES_HDR_LEN);
  /*system header*/
  bits_write( &bitsBuffer, 24,0x000001);  /*start code*/
  bits_write( &bitsBuffer, 8, (stream_id)); /*streamID*/
  bits_write( &bitsBuffer, 16,(payload_len)+13);  /*packet_len*/ //指出pes分组中数据长度和该字节后的长度和
  bits_write( &bitsBuffer, 2, 2 );    /*'10'*/
  bits_write( &bitsBuffer, 2, 0 );    /*scrambling_control*/
  bits_write( &bitsBuffer, 1, 0 );    /*priority*/
  bits_write( &bitsBuffer, 1, 0 );    /*data_alignment_indicator*/
  bits_write( &bitsBuffer, 1, 0 );    /*copyright*/
  bits_write( &bitsBuffer, 1, 0 );    /*original_or_copy*/
    bits_write( &bitsBuffer, 1, 1 );    /*PTS_flag*/
  bits_write( &bitsBuffer, 1, 1 );    /*DTS_flag*/
  bits_write( &bitsBuffer, 1, 0 );    /*ESCR_flag*/
  bits_write( &bitsBuffer, 1, 0 );    /*ES_rate_flag*/
  bits_write( &bitsBuffer, 1, 0 );    /*DSM_trick_mode_flag*/
  bits_write( &bitsBuffer, 1, 0 );    /*additional_copy_info_flag*/
  bits_write( &bitsBuffer, 1, 0 );    /*PES_CRC_flag*/
  bits_write( &bitsBuffer, 1, 0 );    /*PES_extension_flag*/
  bits_write( &bitsBuffer, 8, 10);    /*header_data_length*/ 
  // 指出包含在 PES 分组标题中的可选字段和任何填充字节所占用的总字节数。该字段之前
  //的字节指出了有无可选字段
  /*PTS,DTS*/ 
    bits_write( &bitsBuffer, 4, 3 );                    /*'0011'*/
    bits_write( &bitsBuffer, 3, ((pts)>>30)&0x07 );     /*PTS[32..30]*/
    bits_write( &bitsBuffer, 1, 1 );
    bits_write( &bitsBuffer, 15,((pts)>>15)&0x7FFF);    /*PTS[29..15]*/
    bits_write( &bitsBuffer, 1, 1 );
    bits_write( &bitsBuffer, 15,(pts)&0x7FFF);          /*PTS[14..0]*/
    bits_write( &bitsBuffer, 1, 1 );
    bits_write( &bitsBuffer, 4, 1 );                    /*'0001'*/
    bits_write( &bitsBuffer, 3, ((dts)>>30)&0x07 );     /*DTS[32..30]*/
    bits_write( &bitsBuffer, 1, 1 );
    bits_write( &bitsBuffer, 15,((dts)>>15)&0x7FFF);    /*DTS[29..15]*/
    bits_write( &bitsBuffer, 1, 1 );
    bits_write( &bitsBuffer, 15,(dts)&0x7FFF);          /*DTS[14..0]*/
    bits_write( &bitsBuffer, 1, 1 );
  return 0;
}
int main()
{
  if ((_socketFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    printf("创建套接字失败:");
    return -1;
  }
 
  int ul = 1;
  int ret = ioctl(_socketFd, FIONBIO, &ul); //设置为非阻塞模式
  if (ret == -1) {
    printf("设置非阻塞失败!");
  }
  Data_Info_s pPacker;
  pPacker.IFrame = 0;
  pPacker.u32Ssrc = 1234567890123;
  pPacker.s64CurPts = 0;
  FILE* fp = fopen("./test01.h264", "rb");
  char* buf = (char*)malloc(1024 * 1024);
  while(1) {
    int size = getNextNalu(fp, (unsigned char *)(buf), &pPacker);
    if (size <= 0) {
      break;
    }
    gb28181_streampackageForH264(buf, size, &pPacker, 0);
    pPacker.s64CurPts += 3600;
    //usleep(40*1000);
  }
  fclose(fp);
  return 0;
  }
