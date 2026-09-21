const $ = id => document.getElementById(id);

document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(x => x.classList.remove("active"));
    btn.classList.add("active");
    $(btn.dataset.tab).classList.add("active");
  });
});

function preview(inputId, previewId){
  const file = $(inputId).files[0];
  if(!file) return;
  const url = URL.createObjectURL(file);
  $(previewId).innerHTML = `<img src="${url}" alt="preview">`;
}
$("encodeImage").addEventListener("change", async e => {
  preview("encodeImage","encodePreview");
  const fd = new FormData(); fd.append("image", e.target.files[0]);
  const r = await fetch("/api/capacity",{method:"POST",body:fd});
  const d = await r.json();
  $("capacity").textContent = d.capacity_kb ? `Approx. raw LSB capacity: ${d.capacity_kb} KB (${d.width}×${d.height})` : d.error;
});
$("decodeImage").addEventListener("change", e => preview("decodeImage","decodePreview"));

function togglePassword(id){
  const el=$(id); el.type = el.type==="password" ? "text" : "password";
}

async function encode(){
  const file=$("encodeImage").files[0], message=$("message").value, password=$("encPassword").value;
  if(!file || !message || !password){show("encodeMsg","Please fill image, message and password.","error");return;}
  const fd=new FormData();
  fd.append("image",file); fd.append("message",message); fd.append("password",password); fd.append("resilience",$("resilience").value);
  show("encodeMsg","Encrypting and embedding...","");
  const r=await fetch("/api/encode",{method:"POST",body:fd});
  if(!r.ok){const d=await r.json();show("encodeMsg",d.error||"Encoding failed.","error");return;}
  const blob=await r.blob();
  const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="stegovault_encoded.png";a.click();
  show("encodeMsg","Done! Encoded PNG downloaded. Keep the password safe.","success");
}

async function decode(){
  const file=$("decodeImage").files[0], password=$("decPassword").value;
  if(!file || !password){show("decodeMsg","Please select the encoded PNG and enter the password.","error");return;}
  const fd=new FormData();fd.append("image",file);fd.append("password",password);fd.append("resilience",$("decResilience").value);
  show("decodeMsg","Decoding...","");
  const r=await fetch("/api/decode",{method:"POST",body:fd}); const d=await r.json();
  if(!r.ok){show("decodeMsg",d.error||"Decoding failed.","error");return;}
  $("decodedText").value=d.message;show("decodeMsg","Message decoded successfully.","success");
}

async function convertBinary(mode){
  const value=mode==="text_to_binary"?$("textInput").value:$("binaryInput").value;
  const fd=new FormData();fd.append("mode",mode);fd.append("value",value);
  const r=await fetch("/api/binary",{method:"POST",body:fd});const d=await r.json();
  $("binaryResult").textContent=d.result||d.error||"";
}

function show(id,text,cls){
  $(id).textContent=text;$(id).className="message "+cls;
}
