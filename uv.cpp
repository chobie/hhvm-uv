#include "uv.h"

#include "hphp/runtime/ext/std/ext_std_variable.h"
#include "hphp/runtime/base/variable-serializer.h"
#include "hphp/runtime/base/variable-unserializer.h"
#include "hphp/runtime/base/builtin-functions.h"
#include "hphp/runtime/ext/ext_closure.h"
#include "hphp/runtime/base/base-includes.h"

namespace HPHP {

namespace {

enum UVResourceType : long {
  TYPE_TIMER,
};

class UVResource : public SweepableResourceData {
  DECLARE_RESOURCE_ALLOCATION(UVResource);
  uv_timer_t timer;
  enum UVResourceType type;
  Variant callback;
public:
  explicit UVResource();
  explicit UVResource(UVResourceType type, uv_loop_t *loop);
  ~UVResource();
  static StaticString s_class_name;

  virtual const String& o_getClassNameHook() const {
    return s_class_name;
  }

  virtual bool isResource() const {
    return (bool)1;
  }

  static UVResource *Get(const Variant& resource);
  uv_timer_t *GetTimer();

  const Variant& GetCallback();
  void SetCallback(const Variant& callback);
};
}

///////////////////////////////////////////////

StaticString UVResource::s_class_name("uv resource");

UVResource *UVResource::Get(const Variant& resource) {
    if (resource.isNull()) {
        return nullptr;
    }

    UVResource *uv = resource.toResource().getTyped<UVResource>
        (!RuntimeOption::ThrowBadTypeExceptions,
         !RuntimeOption::ThrowBadTypeExceptions);
    return uv;
}
const Variant& UVResource::GetCallback() {
  return this->callback;
}

void UVResource::SetCallback(const Variant& callable) {
  callback = callable;
}

uv_timer_t *UVResource::GetTimer()
{
  return &this->timer;
}

void UVResource::sweep() {
}

UVResource::UVResource() {
}

UVResource::UVResource(UVResourceType type, uv_loop_t *loop) {
  if (loop == NULL) {
    loop = uv_default_loop();
  }

  if (type == TYPE_TIMER) {
     uv_timer_init(loop, &this->timer);
     this->timer.data = this;
  }
}

UVResource::~UVResource() {
}


///////////////////////////////////////////////

static void HHVM_FUNCTION(uv_run) {
  uv_loop_t *loop = uv_default_loop();
  uv_run(loop, UV_RUN_DEFAULT);

  return;
}

static Variant HHVM_FUNCTION(uv_timer_init, const Resource& res_loop) {
  UVResource *uv = nullptr;
  uv_loop_t *loop = NULL;

  if (loop == nullptr) {
    loop = uv_default_loop();
  } else {
    // TODO
  }

  loop = uv_default_loop();
  uv = NEWOBJ(UVResource)(TYPE_TIMER, loop);
  return Resource(uv);
}

static Variant HHVM_FUNCTION(uv_default_loop) {
  UVResource *uv = nullptr;
  uv = NEWOBJ(UVResource)();

  return Resource(uv);
}

static void php_uv_timer_cb(uv_timer_t *handle, int status)
{
	UVResource *uv = (UVResource*)handle->data;
  Array ret = Array::Create();

  vm_call_user_func(uv->GetCallback(), ret);
}

static void HHVM_FUNCTION(uv_timer_start,
  const Resource& res_timer, int64_t timeout, int64_t repeat, const Variant& callable) {

  UVResource *timer = UVResource::Get(res_timer);
  timer->SetCallback(callable);

  uv_timer_start(timer->GetTimer(), php_uv_timer_cb, timeout, repeat);
  return;
}


namespace {
static class UvExtension : public Extension {
 public:
  UvExtension() : Extension("uv") {}

  virtual void moduleInit() {
    HHVM_FE(uv_timer_init);
    HHVM_FE(uv_timer_start);
    HHVM_FE(uv_run);
    HHVM_FE(uv_default_loop);

    loadSystemlib();
  }
} s_uv_extension;
}

HHVM_GET_MODULE(uv)

} // namespace HPHP
