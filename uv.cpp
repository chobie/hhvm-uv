#include "uv.h"
#include "http_parser.h"

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

class UVHttpParserResource : public SweepableResourceData {
  DECLARE_RESOURCE_ALLOCATION(UVHttpParserResource);
public:
  struct http_parser m_parser;
  struct http_parser_url m_handle;
  struct http_parser_settings m_settings;
  int m_is_response;
  int m_was_header_value;
  int m_finished;
  Array *m_result;
  Array m_headers;
  char *m_tmp;
  size_t m_tmp_len;

  explicit UVHttpParserResource(int64_t target);
  ~UVHttpParserResource();
  static StaticString s_class_name;

  virtual const String& o_getClassNameHook() const {
    return s_class_name;
  }

  virtual bool isResource() const {
    return (bool)1;
  }

  static UVHttpParserResource *Get(const Variant& resource);
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
StaticString UVHttpParserResource::s_class_name("uv http parser resource");

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

// HTTP Parser
UVHttpParserResource *UVHttpParserResource::Get(const Variant& resource) {
    if (resource.isNull()) {
        return nullptr;
    }

    UVHttpParserResource *uv = resource.toResource().getTyped<UVHttpParserResource>
        (!RuntimeOption::ThrowBadTypeExceptions,
         !RuntimeOption::ThrowBadTypeExceptions);
    return uv;
}

void UVHttpParserResource::sweep() {
}


/*  http parser callbacks */
static int on_message_begin(http_parser *p)
{
  return 0;
}

static int on_headers_complete(http_parser *p)
{
  return 0;
}

static int on_message_complete(http_parser *p)
{
  UVHttpParserResource *result = static_cast<UVHttpParserResource*>(p->data);
  result->m_finished = 1;

  if (result->m_tmp != NULL) {
    free(result->m_tmp);
    result->m_tmp = NULL;
    result->m_tmp_len = 0;
  }

  return 0;
}

#define PHP_HTTP_PARSER_PARSE_URL(flag, name) \
  if (result->m_handle.field_set & (1 << flag)) { \
    const char *tmp_name = at+result->m_handle.field_data[flag].off; \
    int length = result->m_handle.field_data[flag].len; \
    data->add(String(#name), String(const_cast<char*>(tmp_name), length, CopyString), true); \
  }

static int on_url_cb(http_parser *p, const char *at, size_t len)
{
  UVHttpParserResource *result = static_cast<UVHttpParserResource*>(p->data);
  Array *data = &result->m_headers;

  http_parser_parse_url(at, len, 0, &result->m_handle);

  data->add(String("QUERY_STRING"), String(const_cast<char*>(at), static_cast<int>(len), CopyString), true);
  PHP_HTTP_PARSER_PARSE_URL(UF_SCHEMA, SCHEME);
  PHP_HTTP_PARSER_PARSE_URL(UF_HOST, HOST);
  PHP_HTTP_PARSER_PARSE_URL(UF_PORT, PORT);
  PHP_HTTP_PARSER_PARSE_URL(UF_PATH, PATH);
  PHP_HTTP_PARSER_PARSE_URL(UF_QUERY, QUERY);
  PHP_HTTP_PARSER_PARSE_URL(UF_FRAGMENT, FRAGMENT);

  return 0;
}

static int on_status_cb(http_parser *p, const char *at, size_t len)
{
  return 0;
}

char *php_uv_strtoupper(char *s, size_t len)
{
  unsigned char *c, *e;

  c = (unsigned char *)s;
  e = (unsigned char *)c+len;

  while (c < e) {
    *c = toupper(*c);
    if (*c == '-') *c = '_';
    c++;
  }
  return s;
}

static int header_field_cb(http_parser *p, const char *at, size_t len)
{
  UVHttpParserResource *result = static_cast<UVHttpParserResource*>(p->data);

  if (result->m_was_header_value) {
    if (result->m_tmp != NULL) {
      result->m_tmp = NULL;
    }

    result->m_tmp = strndup(at, len);
    php_uv_strtoupper(result->m_tmp, len);
    result->m_tmp_len = len;
  } else {
    result->m_tmp = static_cast<char*>(realloc(result->m_tmp, len + result->m_tmp_len + 1));
    memcpy(result->m_tmp + result->m_tmp_len, at, len);
    result->m_tmp[result->m_tmp_len + len] = '\0';
    result->m_tmp_len = result->m_tmp_len + len;
  }

  result->m_was_header_value = 0;

  return 0;
}

static int header_value_cb(http_parser *p, const char *at, size_t len)
{
  UVHttpParserResource *result = static_cast<UVHttpParserResource*>(p->data);

  if (result->m_was_header_value) {
    Variant rval = result->m_headers.rvalAt(String(result->m_tmp));

    if (!rval.isNull()) {
      String str = rval.toString();
      str += String(const_cast<char*>(at), static_cast<int>(len), CopyString);
    }
  } else {
    result->m_headers.add(String(result->m_tmp), String(const_cast<char*>(at), static_cast<int>(len), CopyString));
  }

  result->m_was_header_value = 1;
  return 0;
}

static int on_body_cb(http_parser *p, const char *at, size_t len)
{
  UVHttpParserResource *result = static_cast<UVHttpParserResource*>(p->data);
  result->m_headers.add(String("BODY"), String(const_cast<char*>(at), static_cast<int>(len), CopyString));

  return 0;
}
/* end of callback */

UVHttpParserResource::UVHttpParserResource(int64_t target)
  : m_was_header_value(1), m_finished(0){
  http_parser_init(&m_parser, static_cast<http_parser_type>(target));

  if (target == HTTP_RESPONSE) {
    m_is_response = 1;
  } else {
    m_is_response = 0;
  }

  m_headers = Array::Create();
  memset(&m_handle, 0, sizeof(struct http_parser_url));

  /* setup callback */
  m_settings.on_message_begin = on_message_begin;
  m_settings.on_header_field = header_field_cb;
  m_settings.on_header_value = header_value_cb;
  m_settings.on_url = on_url_cb;
  m_settings.on_status = on_status_cb;
  m_settings.on_body = on_body_cb;
  m_settings.on_headers_complete = on_headers_complete;
  m_settings.on_message_complete = on_message_complete;
}

UVHttpParserResource::~UVHttpParserResource() {
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

  Variant resource = Resource(uv);
  ret.append(resource);

  vm_call_user_func(uv->GetCallback(), ret);
}

static void HHVM_FUNCTION(uv_timer_start,
  const Resource& res_timer, int64_t timeout, int64_t repeat, const Variant& callable) {

  UVResource *timer = UVResource::Get(res_timer);
  timer->SetCallback(callable);

  uv_timer_start(timer->GetTimer(), php_uv_timer_cb, timeout, repeat);
  return;
}

static void HHVM_FUNCTION(uv_timer_stop, const Resource& res_timer)
{
  UVResource *timer = UVResource::Get(res_timer);

  uv_timer_stop(timer->GetTimer());
}

static void HHVM_FUNCTION(uv_timer_again, const Resource& res_timer)
{
  UVResource *timer = UVResource::Get(res_timer);

  uv_timer_again(timer->GetTimer());
}

static void HHVM_FUNCTION(uv_timer_set_repeat, const Resource& res_timer, int64_t repeat)
{
  UVResource *timer = UVResource::Get(res_timer);

  uv_timer_set_repeat(timer->GetTimer(), repeat);
}

static int64_t HHVM_FUNCTION(uv_timer_get_repeat, const Resource& res_timer)
{
  UVResource *timer = UVResource::Get(res_timer);
  int64_t repeat = 0;

  repeat = uv_timer_get_repeat(timer->GetTimer());

  return repeat;
}

// Http Parser
static Variant HHVM_FUNCTION(uv_http_parser_init, int64_t type) {
  UVHttpParserResource *parser = nullptr;

  if (type == 0) {
    type = HTTP_REQUEST;
  }

  parser = NEWOBJ(UVHttpParserResource)(type);

  return Resource(parser);
}

static Variant HHVM_FUNCTION(uv_http_parser_execute, const Resource& res_parser, const String& body, VRefParam arr /* = null */) {
  Array result = Array::Create();
  UVHttpParserResource *parser = UVHttpParserResource::Get(res_parser);
  size_t nparsed = 0;
  char version_buffer[4] = {0};

  if (parser->m_finished == 1) {
    raise_notice("passed uv_parser resource has already finished.");
    return false;
  }

  parser->m_result = &result;
  parser->m_parser.data = parser;
  nparsed = http_parser_execute(&parser->m_parser, &parser->m_settings, body.c_str(), body.length());

  if (nparsed != body.length()) {
    // TODO(chobie): raise an exception
    return false;
  }

  if (parser->m_is_response == 0) {
    result.add(String("REQUEST_METHOD"), String(const_cast<char*>(http_method_str(static_cast<http_method>(parser->m_parser.method)))));
  } else {
    result.add(String("STATUS_CODE"), static_cast<int64_t>(parser->m_parser.status_code));
  }
  result.add(String("UPGRADE"), static_cast<int64_t>(parser->m_parser.upgrade));

  snprintf(version_buffer, 4, "%d.%d", parser->m_parser.http_major, parser->m_parser.http_minor);
  result.add(String("VERSION"), String(version_buffer));
  result.add(String("HEADERS"), parser->m_headers);

  arr = result;
  return true;
}


namespace {
static class UvExtension : public Extension {
 public:
  UvExtension() : Extension("uv") {}

  virtual void moduleInit() {
    // Timer
    HHVM_FE(uv_timer_init);
    HHVM_FE(uv_timer_start);
    HHVM_FE(uv_timer_stop);
    HHVM_FE(uv_timer_again);
    HHVM_FE(uv_timer_set_repeat);
    HHVM_FE(uv_timer_get_repeat);

    // Http Parser
    HHVM_FE(uv_http_parser_init);
    HHVM_FE(uv_http_parser_execute);

    HHVM_FE(uv_run);
    HHVM_FE(uv_default_loop);

    loadSystemlib();
  }
} s_uv_extension;
}

HHVM_GET_MODULE(uv)

} // namespace HPHP
