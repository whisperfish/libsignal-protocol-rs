(function() {var implementors = {};
implementors["backtrace"] = [{"text":"impl RefUnwindSafe for Frame","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Symbol","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for SymbolName&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a, 'b&gt; !RefUnwindSafe for BacktraceFmt&lt;'a, 'b&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'fmt, 'a, 'b&gt; !RefUnwindSafe for BacktraceFrameFmt&lt;'fmt, 'a, 'b&gt;","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Backtrace","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for BacktraceFrame","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for BacktraceSymbol","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for BytesOrWideString&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PrintFmt","synthetic":true,"types":[]}];
implementors["base64"] = [{"text":"impl RefUnwindSafe for Config","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for DecodeError","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for CharacterSet","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for Base64Display&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a, R&gt; RefUnwindSafe for DecoderReader&lt;'a, R&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;R: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;W&gt; RefUnwindSafe for EncoderWriter&lt;W&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;W: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;S&gt; RefUnwindSafe for EncoderStringWriter&lt;S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;S: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]}];
implementors["block_modes"] = [{"text":"impl RefUnwindSafe for BlockModeError","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for InvalidKeyIvLength","synthetic":true,"types":[]},{"text":"impl&lt;C, P&gt; RefUnwindSafe for Cbc&lt;C, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;C as BlockCipher&gt;::BlockSize as ArrayLength&lt;u8&gt;&gt;::ArrayType: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;C, P&gt; RefUnwindSafe for Cfb&lt;C, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;C as BlockCipher&gt;::BlockSize as ArrayLength&lt;u8&gt;&gt;::ArrayType: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;C, P&gt; RefUnwindSafe for Cfb8&lt;C, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;C as BlockCipher&gt;::BlockSize as ArrayLength&lt;u8&gt;&gt;::ArrayType: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;C, P&gt; RefUnwindSafe for Ecb&lt;C, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;C, P&gt; RefUnwindSafe for Ofb&lt;C, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;C as BlockCipher&gt;::BlockSize as ArrayLength&lt;u8&gt;&gt;::ArrayType: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;C, P&gt; RefUnwindSafe for Pcbc&lt;C, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;C as BlockCipher&gt;::BlockSize as ArrayLength&lt;u8&gt;&gt;::ArrayType: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]}];
implementors["digest"] = [{"text":"impl RefUnwindSafe for InvalidOutputSize","synthetic":true,"types":[]}];
implementors["failure"] = [{"text":"impl !RefUnwindSafe for Backtrace","synthetic":true,"types":[]},{"text":"impl&lt;E&gt; RefUnwindSafe for Compat&lt;E&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;E: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;D&gt; !RefUnwindSafe for Context&lt;D&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; RefUnwindSafe for SyncFailure&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for Error","synthetic":true,"types":[]},{"text":"impl&lt;'f&gt; !RefUnwindSafe for Causes&lt;'f&gt;","synthetic":true,"types":[]}];
implementors["getrandom"] = [{"text":"impl RefUnwindSafe for Error","synthetic":true,"types":[]}];
implementors["hmac"] = [{"text":"impl&lt;D&gt; RefUnwindSafe for Hmac&lt;D&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;D: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;D as BlockInput&gt;::BlockSize as ArrayLength&lt;u8&gt;&gt;::ArrayType: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]}];
implementors["libsignal_protocol"] = [{"text":"impl !RefUnwindSafe for Address","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Buffer","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for Context","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for HMACBasedKeyDerivationFunction","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PreKeyBundle","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PreKeyBundleBuilder","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for SessionBuilder","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for SessionCipher","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for SessionRecord","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for SessionState","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for StoreContext","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for Error","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for InternalError","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for DefaultCrypto","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for SignalCipherTypeError","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for SignalCipherType","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for IdentityKeyPair","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for KeyPair","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PreKey","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PreKeyList","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PrivateKey","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PublicKey","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for SessionSignedPreKey","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for CiphertextMessage","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for PreKeySignalMessage","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for SignalMessage","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for CiphertextType","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for InMemoryIdentityKeyStore","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for InMemoryPreKeyStore","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for InMemorySignedPreKeyStore","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for InMemorySessionStore","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for SerializedSession","synthetic":true,"types":[]}];
implementors["libsignal_protocol_sys"] = [{"text":"impl RefUnwindSafe for signal_type_base","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_buffer","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_buffer_list","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_int_list","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_context","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_protocol_store_context","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_protocol_address","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_protocol_sender_key_name","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ec_public_key","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ec_private_key","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ec_key_pair","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ec_public_key_list","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for hkdf_context","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_protocol_key_helper_pre_key_list_node","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ciphertext_message","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_message","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for pre_key_signal_message","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for sender_key_message","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for sender_key_distribution_message","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ratchet_chain_key","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ratchet_root_key","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ratchet_identity_key_pair","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ratchet_message_keys","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for session_pre_key","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for session_signed_pre_key","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for session_pre_key_bundle","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for session_builder","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for session_record","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for session_record_state_node","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for session_state","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for session_cipher","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for sender_message_key","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for sender_chain_key","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for sender_key_state","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for sender_key_record","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for group_session_builder","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for group_cipher","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for fingerprint","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for displayable_fingerprint","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for scannable_fingerprint","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for fingerprint_generator","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for device_consistency_signature","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for device_consistency_commitment","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for device_consistency_message","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for device_consistency_signature_list","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for symmetric_signal_protocol_parameters","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for alice_signal_protocol_parameters","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for bob_signal_protocol_parameters","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_crypto_provider","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_protocol_session_store","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_protocol_pre_key_store","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_protocol_signed_pre_key_store","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_protocol_identity_key_store","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for signal_protocol_sender_key_store","synthetic":true,"types":[]}];
implementors["log"] = [{"text":"impl&lt;'a&gt; !RefUnwindSafe for Record&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !RefUnwindSafe for RecordBuilder&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for Metadata&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for MetadataBuilder&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for SetLoggerError","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ParseLevelError","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Level","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LevelFilter","synthetic":true,"types":[]}];
implementors["proc_macro2"] = [{"text":"impl RefUnwindSafe for TokenStream","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LexError","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Span","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Group","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Punct","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Ident","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Literal","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TokenTree","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Delimiter","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Spacing","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for IntoIter","synthetic":true,"types":[]}];
implementors["rand"] = [{"text":"impl RefUnwindSafe for Bernoulli","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Open01","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for OpenClosed01","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Alphanumeric","synthetic":true,"types":[]},{"text":"impl&lt;X&gt; RefUnwindSafe for Uniform&lt;X&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;X as SampleUniform&gt;::Sampler: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Binomial","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Cauchy","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Dirichlet","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Exp","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Exp1","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Beta","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ChiSquared","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for FisherF","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Gamma","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for StudentT","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LogNormal","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Normal","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for StandardNormal","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Pareto","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Poisson","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Triangular","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for UnitCircle","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for UnitSphereSurface","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Weibull","synthetic":true,"types":[]},{"text":"impl&lt;D, R, T&gt; RefUnwindSafe for DistIter&lt;D, R, T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;D: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;R: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;T: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Standard","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for BernoulliError","synthetic":true,"types":[]},{"text":"impl&lt;X&gt; RefUnwindSafe for UniformInt&lt;X&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;X: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;X&gt; RefUnwindSafe for UniformFloat&lt;X&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;X: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for UniformDuration","synthetic":true,"types":[]},{"text":"impl&lt;X&gt; RefUnwindSafe for WeightedIndex&lt;X&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;X: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;X as SampleUniform&gt;::Sampler: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for WeightedError","synthetic":true,"types":[]},{"text":"impl&lt;W&gt; RefUnwindSafe for WeightedIndex&lt;W&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;W: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;W as SampleUniform&gt;::Sampler: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for EntropyRng","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for StdRng","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ThreadRng","synthetic":true,"types":[]},{"text":"impl !RefUnwindSafe for ReadError","synthetic":true,"types":[]},{"text":"impl&lt;R&gt; RefUnwindSafe for ReadRng&lt;R&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;R: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;R, Rsdr&gt; RefUnwindSafe for ReseedingRng&lt;R, Rsdr&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;R: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;Rsdr: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;R as BlockRngCore&gt;::Results: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for StepRng","synthetic":true,"types":[]},{"text":"impl&lt;'a, S:&nbsp;?Sized, T&gt; RefUnwindSafe for SliceChooseIter&lt;'a, S, T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;S: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;T: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for IndexVec","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for IndexVecIter&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for IndexVecIntoIter","synthetic":true,"types":[]}];
implementors["rand_chacha"] = [{"text":"impl RefUnwindSafe for ChaCha12Core","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ChaCha12Rng","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ChaCha20Core","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ChaCha20Rng","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ChaCha8Core","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ChaCha8Rng","synthetic":true,"types":[]}];
implementors["rand_core"] = [{"text":"impl !RefUnwindSafe for Error","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for OsRng","synthetic":true,"types":[]},{"text":"impl&lt;R:&nbsp;?Sized&gt; RefUnwindSafe for BlockRng&lt;R&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;R: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;R as BlockRngCore&gt;::Results: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;R:&nbsp;?Sized&gt; RefUnwindSafe for BlockRng64&lt;R&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;R: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;R as BlockRngCore&gt;::Results: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]}];
implementors["sha2"] = [{"text":"impl RefUnwindSafe for Sha224","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Sha256","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Sha384","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Sha512","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Sha512Trunc224","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Sha512Trunc256","synthetic":true,"types":[]}];
implementors["syn"] = [{"text":"impl RefUnwindSafe for Attribute","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for MetaList","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for MetaNameValue","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Field","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for FieldsNamed","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for FieldsUnnamed","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Variant","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for VisCrate","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for VisPublic","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for VisRestricted","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprArray","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprAssign","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprAssignOp","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprAsync","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprAwait","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprBinary","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprBlock","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprBox","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprBreak","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprCall","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprCast","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprClosure","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprContinue","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprField","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprForLoop","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprGroup","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprIf","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprIndex","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprLet","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprLit","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprLoop","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprMacro","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprMatch","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprMethodCall","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprParen","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprPath","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprRange","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprReference","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprRepeat","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprReturn","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprStruct","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprTry","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprTryBlock","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprTuple","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprType","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprUnary","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprUnsafe","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprWhile","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ExprYield","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Index","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for BoundLifetimes","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ConstParam","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Generics","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LifetimeDef","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PredicateEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PredicateLifetime","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PredicateType","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TraitBound","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeParam","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for WhereClause","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for ImplGenerics&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for Turbofish&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for TypeGenerics&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Lifetime","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LitBool","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LitByte","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LitByteStr","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LitChar","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LitFloat","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LitInt","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LitStr","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Macro","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for DataEnum","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for DataStruct","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for DataUnion","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for DeriveInput","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Abi","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for BareFnArg","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeArray","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeBareFn","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeGroup","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeImplTrait","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeInfer","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeMacro","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeNever","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeParen","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypePath","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypePtr","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeReference","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeSlice","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeTraitObject","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeTuple","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Variadic","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for AngleBracketedGenericArguments","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Binding","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Constraint","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ParenthesizedGenericArguments","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Path","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PathSegment","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for QSelf","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Error","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for AttrStyle","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Meta","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for NestedMeta","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Fields","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Visibility","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Expr","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Member","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for GenericParam","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TraitBoundModifier","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TypeParamBound","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for WherePredicate","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Lit","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for StrStyle","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for MacroDelimiter","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Data","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for BinOp","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for UnOp","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ReturnType","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Type","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for GenericArgument","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for PathArguments","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Underscore","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Abstract","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for As","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Async","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Auto","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Await","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Become","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Box","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Break","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Const","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Continue","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Crate","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Default","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Do","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Dyn","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Else","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Enum","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Extern","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Final","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Fn","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for For","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for If","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Impl","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for In","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Let","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Loop","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Macro","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Match","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Mod","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Move","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Mut","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Override","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Priv","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Pub","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Ref","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Return","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for SelfType","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for SelfValue","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Static","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Struct","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Super","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Trait","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Try","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Type","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Typeof","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Union","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Unsafe","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Unsized","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Use","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Virtual","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Where","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for While","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Yield","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Add","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for AddEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for And","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for AndAnd","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for AndEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for At","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Bang","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Caret","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for CaretEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Colon","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Colon2","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Comma","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Div","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for DivEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Dollar","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Dot","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Dot2","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Dot3","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for DotDotEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Eq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for EqEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Ge","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Gt","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Le","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Lt","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for MulEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Ne","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Or","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for OrEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for OrOr","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Pound","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Question","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for RArrow","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for LArrow","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Rem","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for RemEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for FatArrow","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Semi","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Shl","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ShlEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Shr","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for ShrEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Star","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Sub","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for SubEq","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Tilde","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Brace","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Bracket","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Paren","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Group","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for TokenBuffer","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for Cursor&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T, P&gt; RefUnwindSafe for Punctuated&lt;T, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;T: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;'a, T, P&gt; RefUnwindSafe for Pairs&lt;'a, T, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;T: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;'a, T, P&gt; RefUnwindSafe for PairsMut&lt;'a, T, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;T: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T, P&gt; RefUnwindSafe for IntoPairs&lt;T, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;T: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; RefUnwindSafe for IntoIter&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;'a, T&gt; !RefUnwindSafe for Iter&lt;'a, T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a, T&gt; !RefUnwindSafe for IterMut&lt;'a, T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T, P&gt; RefUnwindSafe for Pair&lt;T, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: RefUnwindSafe,<br>&nbsp;&nbsp;&nbsp;&nbsp;T: RefUnwindSafe,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !RefUnwindSafe for Lookahead1&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !RefUnwindSafe for ParseBuffer&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'c, 'a&gt; RefUnwindSafe for StepCursor&lt;'c, 'a&gt;","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for Nothing","synthetic":true,"types":[]}];
implementors["synstructure"] = [{"text":"impl&lt;'a&gt; RefUnwindSafe for BindingInfo&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for VariantAst&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for VariantInfo&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; RefUnwindSafe for Structure&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for AddBounds","synthetic":true,"types":[]},{"text":"impl RefUnwindSafe for BindStyle","synthetic":true,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()