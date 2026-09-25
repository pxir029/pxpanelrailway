

const url =
    location.origin +
    location.pathname.replace(
        "/p/",
        "/sub-group/"
    );

document.getElementById(
    "subUrl"
).textContent = url;

