// See the file "COPYING" in the main distribution directory for copyright.

// ZAM: Zeek Abstract Machine compiler.

#pragma once

#include "zeek/Event.h"
#include "zeek/script_opt/Expr.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/UseDefs.h"
#include "zeek/script_opt/ZAM/ZBody.h"
#include "zeek/script_opt/ZAM/ZInst.h"

namespace zeek {
class EventHandler;
}

namespace zeek::detail {

class NameExpr;
class ConstExpr;
class FieldExpr;
class ListExpr;

class Stmt;
class SwitchStmt;
class CatchReturnStmt;

using InstLabel = ZInstI*;

// Class representing a single compiled statement.  (This is different from,
// but related to, the ZAM instruction(s) generated for that compilation.)
// Designed to be fully opaque, but also effective without requiring pointer
// management.
class ZAMStmt {
protected:
    friend class ZAMCompiler;

    ZAMStmt() { stmt_num = -1; /* flag that it needs to be set */ }
    ZAMStmt(int _stmt_num) { stmt_num = _stmt_num; }

    int stmt_num;
};

// Class that holds values that only have meaning to the ZAM compiler,
// but that needs to be held (opaquely, via a pointer) by external
// objects.
class OpaqueVals {
public:
    OpaqueVals(ZInstAux* _aux) { aux = _aux; }

    ZInstAux* aux;
};

// Most of the methods for the compiler are either in separate header source
// files, or in headers generated by auxil/gen-zam. We include these within
// the private part of the compiler class definitions, so a few methods that
// need to be public are specified here directly, rather than via such
// headers.
//
// We declare member variables here, rather than in included headers, since
// many of them are used across different source files, and don't necessarily
// have a natural "home".

class ZAMCompiler {
public:
    ZAMCompiler(ScriptFuncPtr f, std::shared_ptr<ProfileFuncs> pfs, std::shared_ptr<ProfileFunc> pf, ScopePtr scope,
                StmtPtr body, std::shared_ptr<UseDefs> ud, std::shared_ptr<Reducer> rd);
    ~ZAMCompiler();

    const FrameReMap& FrameDenizens() const { return shared_frame_denizens_final; }

    const std::vector<int>& ManagedSlots() const { return managed_slotsI; }

    const std::vector<GlobalInfo>& Globals() const { return globalsI; }

    bool NonRecursive() const { return non_recursive; }

    const TableIterVec& GetTableIters() const { return table_iters; }
    int NumStepIters() const { return num_step_iters; }

    template<typename T>
    const CaseMaps<T>& GetCases() const {
        if constexpr ( std::is_same_v<T, zeek_int_t> )
            return int_cases;
        else if constexpr ( std::is_same_v<T, zeek_uint_t> )
            return uint_cases;
        else if constexpr ( std::is_same_v<T, double> )
            return double_cases;
        else if constexpr ( std::is_same_v<T, std::string> )
            return str_cases;
    }

    StmtPtr CompileBody();

    void Dump();

private:
    friend class SimpleZBI;
    friend class CondZBI;
    friend class OptAssignZBI;
    friend class SortZBI;
    friend class CatZBI;
    friend class MultiZBI;

    // The following are used for switch statements, mapping the switch value
    // (which can be any atomic type) to a branch target.  We have vectors of
    // them because functions can contain multiple switches.
    //
    // See ZBody.h for their concrete counterparts, which we've already #include'd.
    template<typename T>
    using CaseMapI = std::map<T, InstLabel>;
    template<typename T>
    using CaseMapsI = std::vector<CaseMapI<T>>;

#include "zeek/script_opt/ZAM/AM-Opt.h"
#include "zeek/script_opt/ZAM/Branches.h"
#include "zeek/script_opt/ZAM/Driver.h"
#include "zeek/script_opt/ZAM/Expr.h"
#include "zeek/script_opt/ZAM/Inst-Gen.h"
#include "zeek/script_opt/ZAM/Low-Level.h"
#include "zeek/script_opt/ZAM/Stmt.h"
#include "zeek/script_opt/ZAM/Vars.h"

// Headers auto-generated by gen-zam.
#include "zeek/ZAM-MethodDecls.h"

    // The first of these is used as we compile down to ZInstI's.
    // The second is the final intermediary code.  They're separate
    // to make it easy to remove dead code.
    std::vector<ZInstI*> insts1;
    std::vector<ZInstI*> insts2;

    // Used as a placeholder when we have to generate a GoTo target
    // beyond the end of what we've compiled so far.
    ZInstI* pending_inst = nullptr;

    // Indices of break/next/fallthrough/catch-return goto's, so they
    // can be patched up post-facto.  These are vectors-of-vectors
    // so that nesting works properly.
    GoToSets breaks;
    GoToSets nexts;
    GoToSets fallthroughs;
    GoToSets catches;

    // The following tracks return variables for catch-returns.
    // Can be nil if the usage doesn't include using the return value
    // (and/or no return value generated).
    std::vector<const NameExpr*> retvars;

    ScriptFuncPtr func;
    std::shared_ptr<ProfileFuncs> pfs;
    std::shared_ptr<ProfileFunc> pf;
    ScopePtr scope;
    StmtPtr body;
    std::shared_ptr<UseDefs> ud;
    std::shared_ptr<Reducer> reducer;

    // Maps identifiers to their (unique) frame location.
    std::unordered_map<const ID*, int> frame_layout1;

    // Inverse mapping, used for tracking frame usage (and for dumping
    // statements).
    FrameMap frame_denizens;

    // The same, but for remapping identifiers to shared frame slots.
    FrameReMap shared_frame_denizens;

    // The same, but renumbered to take into account removal of
    // dead statements.
    FrameReMap shared_frame_denizens_final;

    // Maps frame1 slots to frame2 slots.  A value < 0 means the
    // variable doesn't exist in frame2 - it's an error to encounter
    // one of these when remapping instructions!
    std::vector<int> frame1_to_frame2;

    // A type for mapping an instruction to a set of locals associated
    // with it.
    using AssociatedLocals = std::unordered_map<const ZInstI*, IDSet>;

    // Maps (live) instructions to which frame denizens begin their
    // lifetime via an initialization at that instruction, if any ...
    // (it can be more than one local due to extending lifetimes to
    // span loop bodies)
    AssociatedLocals inst_beginnings;

    // ... and which frame denizens had their last usage at the
    // given instruction.  (These are insts1 instructions, prior to
    // removing dead instructions, compressing the frames, etc.)
    AssociatedLocals inst_endings;

    // A type for inverse mappings.
    using AssociatedInsts = std::unordered_map<int, const ZInstI*>;

    // Inverse mappings: for a given frame denizen's slot, where its
    // lifetime begins and ends.
    AssociatedInsts denizen_beginning;
    AssociatedInsts denizen_ending;

    // In the following, member variables ending in 'I' are intermediary
    // values that get finalized when constructing the corresponding
    // ZBody.
    std::vector<GlobalInfo> globalsI;
    std::unordered_map<const ID*, int> global_id_to_info; // inverse

    // Intermediary switch tables (branching to ZInst's rather
    // than concrete instruction offsets).
    CaseMapsI<zeek_int_t> int_casesI;
    CaseMapsI<zeek_uint_t> uint_casesI;
    CaseMapsI<double> double_casesI;

    // Note, we use this not only for strings but for addresses
    // and prefixes.
    CaseMapsI<std::string> str_casesI;

    // Same, but for the concretized versions.
    CaseMaps<zeek_int_t> int_cases;
    CaseMaps<zeek_uint_t> uint_cases;
    CaseMaps<double> double_cases;
    CaseMaps<std::string> str_cases;

    std::vector<int> managed_slotsI;

    int frame_sizeI;

    TableIterVec table_iters;
    int num_step_iters = 0;

    bool non_recursive = false;

    // Most recent instruction, other than for housekeeping.
    int top_main_inst;

    // Used for communication between Frame1Slot and a subsequent
    // AddInst.  If >= 0, then upon adding the next instruction,
    // it should be followed by Store-Global or Store-Capture for
    // the given slot.
    int pending_global_store = -1;
    int pending_capture_store = -1;
};

// Invokes after compiling all of the function bodies.
class FuncInfo;
extern void finalize_functions(const std::vector<FuncInfo>& funcs);

} // namespace zeek::detail
