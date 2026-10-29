#pragma once
// Experimental, bounded candidate discovery. This is not PE admission.
#include <limits>
#include <iomanip>
#include <llvm/Support/JSON.h>

DEFINE_string(aot_switch_profile, "", "Experimental switch profile: clang-rel32-v1");
DEFINE_string(aot_switch_data_path, "", "Absolute, separate read-only data input <=64KiB");
DEFINE_uint64(aot_switch_data_va, 0, "Guest VA of separate data bytes");
DEFINE_string(aot_switch_proof_path, "", "Python-validated complete proof; exact candidate/code/data binding");
static bool switch_lift_approved=false;

struct SwitchNode {
  uint64_t pc=0, next=0, target=0, imm=0;
  unsigned length=0, width=0, mc=0, scale=0, mw=0;
  int64_t disp=0;
  bool mr=false, mwrite=false;
  std::string cls, r0, r1, mb, mi, bytes;
};
struct SwitchCandidate {
  uint64_t guard, branch, normalize, lea, load, add, jump, table, def;
  std::string index32,index64,base,target;
  std::vector<uint64_t> targets;
  std::vector<int64_t> offsets;
  std::string bytes;
};
static std::map<uint64_t,SwitchNode> switch_nodes;
static std::vector<SwitchCandidate> switch_candidates;
static std::vector<uint8_t> switch_data;
static bool SwitchEnabled() { return !FLAGS_aot_switch_profile.empty(); }
static std::string SwitchHex(const uint8_t *bytes, size_t count) {
  std::ostringstream out; out<<std::hex<<std::setfill('0');
  for(size_t n=0;n<count;++n) out<<std::setw(2)<<unsigned(bytes[n]);
  return out.str();
}
static bool SwitchInitialize(const Memory &memory) {
  if(!SwitchEnabled()) {
    if(!FLAGS_aot_switch_data_path.empty() || FLAGS_aot_switch_data_va) {
      std::cerr<<"REJECT switch data without profile\n";return false;
    }
    return true;
  }
  if(FLAGS_aot_switch_profile!="clang-rel32-v1" || FLAGS_arch!="amd64" ||
     FLAGS_os!="windows" ||
     (FLAGS_aot_decode_only && (!FLAGS_ir_out.empty() || !FLAGS_ir_pre_out.empty() || !FLAGS_bc_out.empty())) ||
     (!FLAGS_aot_decode_only && FLAGS_aot_switch_proof_path.empty()) ||
     !FLAGS_aot_iat_slots.empty() || FLAGS_aot_vtable_mem64 ||
     FLAGS_aot_import_reg64 || FLAGS_aot_inc_base32 ||
     memory.empty() || memory.size()>32768) {
    std::cerr<<"REJECT switch profile currently requires bounded decode mode or explicit proven input\n";return false;
  }
  const std::filesystem::path path(FLAGS_aot_switch_data_path);
  std::error_code error;
  if(!path.is_absolute() || std::filesystem::is_symlink(path,error) || error ||
     !std::filesystem::is_regular_file(path,error) || error) {
    std::cerr<<"REJECT separate regular switch data file required\n";return false;
  }
  auto length=std::filesystem::file_size(path,error);
  auto va=FLAGS_aot_switch_data_va;
  if(error || !length || length>65536 || !va ||
     va>std::numeric_limits<uint64_t>::max()-length ||
     (va<=memory.rbegin()->first && va+length>memory.begin()->first)) {
    std::cerr<<"REJECT switch data extent\n";return false;
  }
  std::ifstream stream(path,std::ios::binary);
  switch_data.resize(length);stream.read(reinterpret_cast<char*>(switch_data.data()),length);
  if(!stream || stream.peek()!=std::char_traits<char>::eof()) {
    std::cerr<<"REJECT switch data read/size changed\n";return false;
  }
  return true;
}
static SwitchNode SwitchRead(uint64_t pc, const xed_decoded_inst_t &d,
                             const remill::Instruction &inst, const uint8_t *raw) {
  SwitchNode n; n.pc=pc;n.next=inst.next_pc;n.target=inst.branch_taken_pc;
  n.length=xed_decoded_inst_get_length(&d);n.cls=xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&d));
  n.width=xed_decoded_inst_get_operand_width(&d);
  n.r0=xed_reg_enum_t2str(xed_decoded_inst_get_reg(&d,XED_OPERAND_REG0));
  n.r1=xed_reg_enum_t2str(xed_decoded_inst_get_reg(&d,XED_OPERAND_REG1));
  n.imm=xed_decoded_inst_get_unsigned_immediate(&d);
  n.mc=xed_decoded_inst_number_of_memory_operands(&d);
  n.mb="INVALID";n.mi="INVALID";
  if(n.mc) {
    n.mb=xed_reg_enum_t2str(xed_decoded_inst_get_base_reg(&d,0));
    n.mi=xed_reg_enum_t2str(xed_decoded_inst_get_index_reg(&d,0));
    n.scale=xed_decoded_inst_get_scale(&d,0);
    n.disp=xed_decoded_inst_get_memory_displacement(&d,0);
    n.mw=xed_decoded_inst_get_memory_operand_length(&d,0)*8;
    n.mr=xed_decoded_inst_mem_read(&d,0);n.mwrite=xed_decoded_inst_mem_written(&d,0);
  }
  n.bytes=SwitchHex(raw,n.length);return n;
}
static std::string SwitchWide(const std::string &r) {
  static const std::map<std::string,std::string> regs={
    {"EAX","RAX"},{"EBX","RBX"},{"ECX","RCX"},{"EDX","RDX"},
    {"ESI","RSI"},{"EDI","RDI"},{"EBP","RBP"},
    {"R8D","R8"},{"R9D","R9"},{"R10D","R10"},{"R11D","R11"},
    {"R12D","R12"},{"R13D","R13"},{"R14D","R14"},{"R15D","R15"}};
  auto it=regs.find(r);return it==regs.end()?"INVALID":it->second;
}
static bool SwitchSignedAdd(uint64_t base,int64_t displacement,uint64_t &out) {
  if(displacement>=0) {
    if(base>UINT64_MAX-uint64_t(displacement))return false;
    out=base+uint64_t(displacement);
  } else {
    const uint64_t amount=uint64_t(-(displacement+1))+1;
    if(base<amount)return false;out=base-amount;
  }
  return true;
}
static bool SwitchDiscover(uint64_t pc,const Memory &memory,std::set<uint64_t> &pending) {
  if(!switch_candidates.empty())return false;
  auto end=switch_nodes.find(pc);if(end==switch_nodes.end())return false;
  std::vector<SwitchNode> seq(7);seq[6]=end->second;
  for(int i=5;i>=0;--i) {
    if(end==switch_nodes.begin())return false;--end;
    seq[i]=end->second;if(seq[i].pc+seq[i].length!=seq[i+1].pc)return false;
  }
  const auto &c=seq[0],&b=seq[1],&z=seq[2],&l=seq[3],&m=seq[4],&a=seq[5],&j=seq[6];
  const auto wide=SwitchWide(c.r0);
  for(const auto &n:seq) std::cerr<<"SWITCH_NODE pc="<<n.pc<<" cls="<<n.cls<<" width="<<n.width
    <<" r0="<<n.r0<<" r1="<<n.r1<<" mc="<<n.mc<<" base="<<n.mb<<" index="<<n.mi
    <<" scale="<<n.scale<<" disp="<<n.disp<<" mw="<<n.mw<<" mr="<<n.mr
    <<" imm="<<n.imm<<" next="<<n.next<<" target="<<n.target<<"\n";
  if(c.cls!="CMP" || c.width!=32 || c.mc || c.imm<1 || c.imm>31 || wide=="INVALID" ||
     c.r1!="RFLAGS" || b.cls!="JNBE" || b.next!=z.pc || !memory.count(b.target) ||
     z.cls!="MOV" || z.width!=32 || z.mc || z.r0!=c.r0 || z.r1!=c.r0 ||
     l.cls!="LEA" || l.width!=64 || l.mc!=1 || l.mb!="RIP" || l.mi!="INVALID" ||
     l.r0=="RSP" || l.r0=="INVALID" || l.r0==wide ||
     m.cls!="MOVSXD" || m.width!=64 || m.mc!=1 || m.mb!=l.r0 || m.mi!=wide ||
     m.scale!=4 || m.disp || m.mw!=32 || !m.mr || m.mwrite ||
     m.r0=="RSP" || m.r0=="INVALID" || m.r0==l.r0 ||
     a.cls!="ADD" || a.width!=64 || a.mc || a.r0!=m.r0 || a.r1!=l.r0 ||
     j.cls!="JMP" || j.width!=64 || j.mc || j.r0!=m.r0)return false;
  uint64_t table=0;if(!SwitchSignedAdd(l.next,l.disp,table))return false;
  const uint64_t count=c.imm+1,va=FLAGS_aot_switch_data_va;
  if(table<va || table-va>switch_data.size() || count*4>switch_data.size()-(table-va))return false;
  SwitchCandidate candidate{c.pc,b.pc,z.pc,l.pc,m.pc,a.pc,j.pc,table,b.target,
                            c.r0,wide,l.r0,m.r0,{},{},{}};
  auto offset=table-va;
  candidate.bytes=SwitchHex(switch_data.data()+offset,count*4);
  for(uint64_t n=0;n<count;++n) {
    auto p=switch_data.data()+offset+n*4;
    uint32_t raw=uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);
    int64_t rel=raw<0x80000000u?int64_t(raw):int64_t(raw)-0x100000000LL;
    uint64_t target=0;if(!SwitchSignedAdd(table,rel,target)||!memory.count(target))return false;
    candidate.offsets.push_back(rel);candidate.targets.push_back(target);pending.insert(target);
  }
  switch_candidates.push_back(std::move(candidate));return true;
}
static void SwitchMetadata(std::ostream &row,const SwitchNode &n) {
  row<<",\"bytes\":\""<<n.bytes<<"\",\"operand_width\":"<<n.width
     <<",\"reg0\":\""<<n.r0<<"\",\"reg1\":\""<<n.r1
     <<"\",\"memory_count\":"<<n.mc<<",\"mem_base\":\""<<n.mb
     <<"\",\"mem_index\":\""<<n.mi<<"\",\"mem_scale\":"<<n.scale
     <<",\"mem_displacement\":"<<n.disp<<",\"mem_width\":"<<n.mw
     <<",\"mem_read\":"<<(n.mr?"true":"false")<<",\"mem_written\":"<<(n.mwrite?"true":"false");
}
static void SwitchCandidatesJSON(std::ostream &out) {
  out<<"[";
  for(size_t i=0;i<switch_candidates.size();++i) {
    if(i)out<<",";const auto &c=switch_candidates[i];
    out<<"{\"guard_pc\":"<<c.guard<<",\"branch_pc\":"<<c.branch
       <<",\"normalize_pc\":"<<c.normalize<<",\"lea_pc\":"<<c.lea
       <<",\"load_pc\":"<<c.load<<",\"add_pc\":"<<c.add<<",\"jump_pc\":"<<c.jump
       <<",\"table_pc\":"<<c.table<<",\"count\":"<<c.targets.size()<<",\"default_pc\":"<<c.def
       <<",\"index_reg32\":\""<<c.index32<<"\",\"index_reg64\":\""<<c.index64
       <<"\",\"base_reg64\":\""<<c.base<<"\",\"target_reg64\":\""<<c.target
       <<"\",\"table_bytes\":\""<<c.bytes<<"\",\"targets\":[";
    for(size_t j=0;j<c.targets.size();++j){if(j)out<<",";out<<c.targets[j];}
    out<<"],\"signed_offsets\":[";
    for(size_t j=0;j<c.offsets.size();++j){if(j)out<<",";out<<c.offsets[j];}
    out<<"]}";
  }
  out<<"]";
}

static bool SwitchApprove(const std::string &packet) {
  if(!SwitchEnabled() || FLAGS_aot_decode_only)return true;
  std::filesystem::path path(FLAGS_aot_switch_proof_path);std::error_code ec;
  if(!path.is_absolute() || std::filesystem::is_symlink(path,ec) || ec ||
     !std::filesystem::is_regular_file(path,ec) || ec || std::filesystem::file_size(path,ec)>1048576 || ec)return false;
  std::ifstream input(path);std::string raw((std::istreambuf_iterator<char>(input)),{});
  auto proof=llvm::json::parse(raw);auto generated=llvm::json::parse(packet);
  if(!proof || !generated){if(!proof)llvm::consumeError(proof.takeError());if(!generated)llvm::consumeError(generated.takeError());return false;}
  auto object=proof->getAsObject();if(!object)return false;
  if(object->getString("status")!=std::optional<llvm::StringRef>("PROVEN_STATIC_NOT_LIFTED"))return false;
  auto candidate=object->get("candidate_packet");if(!candidate || *candidate!=*generated)return false;
  auto text=object->getString("text_bytes"),data=object->getString("data_bytes");
  if(!text || !data || *text!=FLAGS_bytes || *data!=SwitchHex(switch_data.data(),switch_data.size()))return false;
  auto ta=object->getInteger("text_address"),da=object->getInteger("data_address");
  if(!ta || !da || uint64_t(*ta)!=FLAGS_address || uint64_t(*da)!=FLAGS_aot_switch_data_va)return false;
  switch_lift_approved=true;return true;
}
