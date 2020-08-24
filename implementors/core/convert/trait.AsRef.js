(function() {var implementors = {};
implementors["failure"] = [{"text":"impl AsRef&lt;dyn Fail + 'static&gt; for Error","synthetic":false,"types":[]}];
implementors["generic_array"] = [{"text":"impl&lt;T, N&gt; AsRef&lt;[T]&gt; for GenericArray&lt;T, N&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;N: ArrayLength&lt;T&gt;,&nbsp;</span>","synthetic":false,"types":[]}];
implementors["libsignal_protocol"] = [{"text":"impl AsRef&lt;[u8]&gt; for Buffer","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()