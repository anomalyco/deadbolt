//! JVM setup required by reqwest's Android certificate verifier (iroh's HTTPS
//! discovery). Call AndroidRuntime.initialize(applicationContext) before new().
use jni::{Env, bind_java_type, native_method, objects::JClass};

bind_java_type! { Context => android.content.Context }

#[expect(
    deprecated,
    reason = "jni 0.22's generated ABI check uses AtomicBool::fetch_update"
)]
const _: jni::NativeMethod = native_method! {
    java_type = "pw.deadbolt.mobile.core.AndroidRuntime",
    type_map = { Context => android.content.Context },
    static extern fn initialize(context: Context),
};

fn initialize<'local>(
    env: &mut Env<'local>,
    _: JClass<'local>,
    context: Context<'local>,
) -> jni::errors::Result<()> {
    rustls_platform_verifier::android::init_with_env(env, context.into())
}
