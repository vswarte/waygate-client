use std::sync::Arc;
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::singleton::DLRFLocatable;
use pelite::pe::{Pe, PeView};
use pelite::pattern::Atom;
use windows::{core::PCSTR, Win32::System::LibraryLoader::GetModuleHandleA};
use std::sync::LazyLock;

pub trait TaskRuntime {
    fn run_task<T: Into<FD4Task>>(&self, execute: T, group: CSTaskGroupIndex) -> TaskHandle;
}

const REGISTER_TASK_PATTERN: &[Atom] =
    pelite::pattern!("e8 ? ? ? ? 48 8b 0d ? ? ? ? 4c 8b c7 8b d3 e8 $ { ' }");

const REGISTER_TASK_VA: LazyLock<u64> = LazyLock::new(|| {
    let module = unsafe {
        let handle = GetModuleHandleA(PCSTR(std::ptr::null())).unwrap().0 as *const u8;
        PeView::module(handle)
    };

    let mut matches = [0u32; 2];
    if !module
        .scanner()
        .finds_code(REGISTER_TASK_PATTERN, &mut matches)
    {
        panic!("Could not find REGISTER_TASK_PATTERN or found duplicates.");
    }

    module
        .rva_to_va(matches[1])
        .expect("Call target for REGISTER_TASK_PATTERN was not in exe")
});

impl TaskRuntime for CSTaskImp {
    fn run_task<T: Into<FD4Task>>(&self, task: T, group: CSTaskGroupIndex) -> TaskHandle {
        let register_task: extern "C" fn(&CSTaskImp, CSTaskGroupIndex, &FD4Task) =
            unsafe { std::mem::transmute(*REGISTER_TASK_VA) };

        let task: Arc<FD4Task> = Arc::new(task.into());
        // SAFETY: we hold a unique reference to the contents of `arc`
        unsafe {
            *task.self_ref.get() = Some(task.clone());
        }

        register_task(self, group, task.as_ref());

        TaskHandle { _task: task }
    }
}

pub struct TaskHandle {
    _task: Arc<FD4Task>,
}

impl Drop for TaskHandle {
    fn drop(&mut self) {
        todo!("Call the actual unregister fn from the game");
        // self._task.unregister()
    }
}

trait FD4TaskVMT: 'static + Sized {
    fn vmt() -> *const extern "C" fn() -> () {
        #[repr(C)]
        struct Layout<T>(
            extern "C" fn(&T) -> *mut (),
            extern "C" fn(&mut T),
            extern "C" fn(&mut T, &FD4TaskData),
        );

        let vmt: &'static _ = &Layout(Self::get_runtime_class, Self::destructor, Self::execute);
        vmt as *const _ as *const extern "C" fn() -> ()
    }

    extern "C" fn get_runtime_class(&self) -> *mut () {
        unimplemented!()
    }
    extern "C" fn destructor(&mut self) {
        unimplemented!()
    }

    extern "C" fn execute(&mut self, data: &FD4TaskData);
}

#[repr(C)]
pub struct FD4Task {
    vftable: *const extern "C" fn() -> (),
    unk8: usize,
    closure: Box<dyn FnMut(&FD4TaskData)>,
    unregister_requested: AtomicBool,
    self_ref: UnsafeCell<Option<Arc<Self>>>,
}

impl FD4TaskVMT for FD4Task {
    extern "C" fn execute(&mut self, data: &FD4TaskData) {
        // Should we stop before run?
        // if !self.unregister_requested.load(Ordering::Relaxed) {
            (self.closure)(data);
        // }

        // Drop if we got cancelled during run.
        // if self.unregister_requested.load(Ordering::Relaxed) {
        //     self.self_ref.get_mut().take();
        // }
    }
}

impl FD4Task {
    pub fn new<F: FnMut(&FD4TaskData) + 'static + Send>(closure: F) -> Self {
        Self {
            vftable: Self::vmt(),
            unk8: 0,
            closure: Box::new(closure),
            unregister_requested: AtomicBool::new(false),
            self_ref: UnsafeCell::new(None),
        }
    }

    // fn unregister(&self) {
    //     self.unregister_requested.store(true, Ordering::Relaxed);
    // }
}

impl<F: FnMut(&FD4TaskData) + 'static + Send> From<F> for FD4Task {
    fn from(value: F) -> Self {
        Self::new(value)
    }
}

impl Drop for FD4Task {
    fn drop(&mut self) {
        self.unregister_requested.store(true, Ordering::Relaxed);
    }
}

#[repr(C)]
pub struct CSTaskImp {
    pub vftable: usize,
    pub task_impl: usize,
}

impl DLRFLocatable for CSTaskImp {
    const DLRF_NAME: &'static str = "CSTask";
}

#[repr(C)]
pub struct FD4Time {
    pub vftable: usize,
    pub time: f32,
    _padc: u32,
}

#[repr(C)]
pub struct FD4TaskData {
    delta_time: FD4Time,
    task_group_id: u32,
    seed: i32,
}

#[repr(u32)]
#[allow(non_camel_case_types, dead_code)]
pub enum CSTaskGroupIndex {
    FrameBegin,
    SteamThread0,
    SteamThread1,
    SteamThread2,
    SteamThread3,
    SteamThread4,
    SteamThread5,
    SystemStep,
    ResStep,
    PadStep,
    GameFlowStep,
    EndShiftWorldPosition,
    GameMan,
    TaskLineIdx_Sys,
    TaskLineIdx_Test,
    TaskLineIdx_NetworkFlowStep,
    TaskLineIdx_InGame_InGameStep,
    TaskLineIdx_InGame_InGameStayStep,
    MovieStep,
    RemoStep,
    TaskLineIdx_InGame_MoveMapStep,
    FieldArea_EndWorldAiManager,
    EmkSystem_Pre,
    EmkSystem_ConditionStatus,
    EmkSystem_Post,
    EventMan,
    FlverResDelayDelectiionBegin,
    TaskLineIdx_InGame_FieldAreaStep,
    TaskLineIdx_InGame_TestNetStep,
    TaskLineIdx_InGame_InGameMenuStep,
    TaskLineIdx_InGame_TitleMenuStep,
    TaskLineIdx_InGame_CommonMenuStep,
    TaskLineIdx_FrpgNet_Sys,
    TaskLineIdx_FrpgNet_Lobby,
    TaskLineIdx_FrpgNet_ConnectMan,
    TaskLineIdx_FrpgNet_Connect,
    TaskLineIdx_FrpgNet_Other,
    SfxMan,
    FaceGenMan,
    FrpgNetMan,
    NetworkUserManager,
    SessionManager,
    BlockList,
    LuaConsoleServer,
    RmiMan,
    ResMan,
    SfxDebugger,
    REMOTEMAN,
    Geom_WaitActivateFade,
    Geom_UpdateDraw,
    Grass_BatchUpdate,
    Grass_ResourceLoadKick,
    Grass_ResourceLoad,
    Grass_ResourceCleanup,
    WorldChrMan_Respawn,
    WorldChrMan_Prepare,
    ChrIns_CalcUpdateInfo_PerfBegin,
    ChrIns_CalcUpdateInfo,
    ChrIns_CalcUpdateInfo_PerfEnd,
    WorldChrMan_PrePhysics,
    WorldChrMan_CalcOmissionLevel_Begin,
    WorldChrMan_CalcOmissionLevel,
    WorldChrMan_CalcOmissionLevel_End,
    WorldChrMan_ConstructUpdateList,
    WorldChrMan_ChrNetwork,
    ChrIns_Prepare,
    ChrIns_NaviCache,
    ChrIns_AILogic_PerfBegin,
    ChrIns_AILogic,
    ChrIns_AILogic_PerfEnd,
    AI_SimulationStep,
    ChrIns_PreBehavior,
    ChrIns_PreBehaviorSafe,
    GeomModelInsCreatePartway_Begin,
    HavokBehavior,
    GeomModelInsCreatePartway_End,
    ChrIns_BehaviorSafe,
    ChrIns_PrePhysics_Begin,
    ChrIns_PrePhysics,
    ChrIns_PrePhysics_End,
    NetFlushSendData,
    ChrIns_PrePhysicsSafe,
    ChrIns_RagdollSafe,
    ChrIns_GarbageCollection,
    GeomModelInsCreate,
    AiBeginCollectGabage,
    WorldChrMan_Update_RideCheck,
    InGameDebugViewer,
    LocationStep,
    LocationUpdate_PrePhysics,
    LocationUpdate_PrePhysics_Parallel,
    LocationUpdate_PrePhysics_Post,
    LocationUpdate_PostCloth,
    LocationUpdate_PostCloth_Parallel,
    LocationUpdate_PostCloth_Post,
    LocationUpdate_DebugDraw,
    EventCondition_BonfireNearEnemyCheck,
    HavokWorldUpdate_Pre,
    RenderingSystemUpdate,
    HavokWorldUpdate_Post,
    ChrIns_PreCloth,
    ChrIns_PreClothSafe,
    HavokClothUpdate_Pre_AddRemoveRigidBody,
    HavokClothUpdate_Pre_ClothModelInsSafe,
    HavokClothUpdate_Pre_ClothModelIns,
    HavokClothUpdate_Pre_ClothManager,
    CameraStep,
    DrawParamUpdate,
    GetNPAuthCode,
    SoundStep,
    HavokClothUpdate_Post_ClothManager,
    HavokClothUpdate_Post_ClothModelIns,
    HavokClothVertexUpdateFinishWait,
    ChrIns_PostPhysics,
    ChrIns_PostPhysicsSafe,
    CSDistViewManager_Update,
    HavokAi_SilhouetteGeneratorHelper_Begin,
    WorldChrMan_PostPhysics,
    GameFlowInGame_MoveMap_PostPhysics_0,
    HavokAi_SilhouetteGeneratorHelper_End,
    DmgMan_Pre,
    DmgMan_ShapeCast,
    DmgMan_Post,
    GameFlowInGame_MoveMap_PostPhysics_1_Core0,
    GameFlowInGame_MoveMap_PostPhysics_1_Core1,
    GameFlowInGame_MoveMap_PostPhysics_1_Core2,
    MenuMan,
    WorldChrMan_Update_BackreadRequestPre,
    ChrIns_Update_BackreadRequest,
    WorldChrMan_Update_BackreadRequestPost,
    HavokAi_World,
    WorldAiManager_BeginUpdateFormation,
    WorldAiManager_EndUpdateFormation,
    GameFlowInGame_TestNet,
    GameFlowInGame_InGameMenu,
    GameFlowInGame_TitleMenu,
    GameFlowInGame_CommonMenu,
    GameFlowFrpgNet_Sys,
    GameFlowFrpgNet_Lobby,
    GameFlowFrpgNet_ConnectMan,
    GameFlowFrpgNet_Connect,
    GameFlowStep_Post,
    ScaleformStep,
    FlverResDelayDelectiionEnd,
    Draw_Pre,
    GraphicsStep,
    DebugDrawMemoryBar,
    DbgMenuStep,
    DbgRemoteStep,
    PlaylogSystemStep,
    ReviewMan,
    ReportSystemStep,
    DbgDispStep,
    DrawStep,
    DrawBegin,
    GameSceneDraw,
    AdhocDraw,
    DrawEnd,
    Draw_Post,
    SoundPlayLimitterUpdate,
    BeginShiftWorldPosition,
    FileStep,
    FileStepUpdate_Begin,
    FileStepUpdate_End,
    Flip,
    DelayDeleteStep,
    AiEndCollectGabage,
    RecordHeapStats,
    FrameEnd,
}
