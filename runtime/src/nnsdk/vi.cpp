// nn::vi (pantalla y capa) y nv:: (arranque del driver). En Android solo hay una ventana:
// la de la APK, que es lo que devuelve GetNativeWindow y luego recibe NVN.

#include <time.h>

#include <cstddef>
#include <mutex>
#include <thread>
#include <vector>

#include "nnsdk/os.h"
#include "nnsdk/runtime.h"
#include "nnsdk/types.h"

namespace nn::vi {

struct Display;
struct Layer;

namespace {
char g_display, g_layer;
}

void Initialize() {}
void Finalize() {}

// El evento de vsync de la pantalla: un hilo lo señala a 60 Hz (Unity espera en él para su ritmo de frames).
Result GetDisplayVsyncEvent(os::SystemEventType* event, Display*) {
    static std::mutex m;
    static std::vector<os::SystemEventType*> events;
    nnsdk::create_system_event(event, true, false);
    std::lock_guard lock(m);
    events.push_back(event);
    static std::once_flag once;
    std::call_once(once, [] {
        std::thread([] {
            timespec next;
            clock_gettime(CLOCK_MONOTONIC, &next);
            for (;;) {
                next.tv_nsec += 16'666'667;
                if (next.tv_nsec >= 1'000'000'000) {
                    next.tv_nsec -= 1'000'000'000;
                    next.tv_sec++;
                }
                clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, nullptr);
                std::lock_guard lock(m);
                for (os::SystemEventType* e : events) nnsdk::signal_system_event(e);
            }
        }).detach();
    });
    return ResultSuccess;
}

Result OpenDefaultDisplay(Display** out) {
    *out = reinterpret_cast<Display*>(&g_display);
    return ResultSuccess;
}

void CloseDisplay(Display*) {}

Result CreateLayer(Layer** out, Display*) {
    *out = reinterpret_cast<Layer*>(&g_layer);
    return ResultSuccess;
}
// La ventana es de la APK y sigue viva hasta que Android la destruya.
void DestroyLayer(Layer*) {}

// Sin ventana (terminal) se devuelve error: el juego no tiene dónde presentar.
Result GetNativeWindow(void** out, Layer*) {
    *out = nnsdk::host().native_window;
    return *out ? ResultSuccess : Result{0x272};
}

}  // namespace nn::vi

namespace nv {

void InitializeGraphics(void*, size_t) {}
void FinalizeGraphics() {}
void SetGraphicsAllocator(void* (*)(size_t, size_t, void*), void (*)(void*, void*), void* (*)(void*, size_t, void*),
                          void*) {}
void SetGraphicsDevtoolsAllocator(void* (*)(size_t, size_t, void*), void (*)(void*, void*),
                                  void* (*)(void*, size_t, void*), void*) {}

}  // namespace nv
