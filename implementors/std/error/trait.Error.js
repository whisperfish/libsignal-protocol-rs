(function() {var implementors = {};
implementors["base64"] = [{"text":"impl Error for DecodeError","synthetic":false,"types":[]}];
implementors["block_modes"] = [{"text":"impl Error for BlockModeError","synthetic":false,"types":[]},{"text":"impl Error for InvalidKeyIvLength","synthetic":false,"types":[]}];
implementors["digest"] = [{"text":"impl Error for InvalidOutputSize","synthetic":false,"types":[]}];
implementors["failure"] = [{"text":"impl&lt;E:&nbsp;Display + Debug&gt; Error for Compat&lt;E&gt;","synthetic":false,"types":[]}];
implementors["getrandom"] = [{"text":"impl Error for Error","synthetic":false,"types":[]}];
implementors["libsignal_protocol"] = [{"text":"impl Error for InternalError","synthetic":false,"types":[]}];
implementors["log"] = [{"text":"impl Error for SetLoggerError","synthetic":false,"types":[]},{"text":"impl Error for ParseLevelError","synthetic":false,"types":[]}];
implementors["rand"] = [{"text":"impl Error for BernoulliError","synthetic":false,"types":[]},{"text":"impl Error for WeightedError","synthetic":false,"types":[]},{"text":"impl Error for ReadError","synthetic":false,"types":[]}];
implementors["rand_core"] = [{"text":"impl Error for Error","synthetic":false,"types":[]}];
implementors["rand_jitter"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/std/error/trait.Error.html\" title=\"trait std::error::Error\">Error</a> for <a class=\"enum\" href=\"rand_jitter/enum.TimerError.html\" title=\"enum rand_jitter::TimerError\">TimerError</a>","synthetic":false,"types":["rand_jitter::error::TimerError"]}];
implementors["syn"] = [{"text":"impl Error for Error","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()