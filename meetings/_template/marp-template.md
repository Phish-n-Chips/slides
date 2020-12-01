---
marp: true
title: "@@@ PUT TITLE HERE @@@"
theme: default
paginate: true
footer: Phish'n'Chips Team, CC-BY 4.0
style: |
    section {
        font-family: Oxygen, Roboto, Ubuntu, "Open Sans", "FreeSans", sans-serif;
        background-position: 0% 100%;
        background-repeat: no-repeat;
        background-size: 200px;
        justify-content: flex-start;
        background-image: url('../_template/style/pnc_logo_typeA_normal_alpha.svg');
    }
    section::after {
        right: 0; bottom: 0; width: 80px; height: 80px; padding: 30px;
        background: url('../_template/style/pagenum-bg.svg') no-repeat center center;
        font-size: 30px;
        text-align: right;
        display: flex;
        align-items: flex-end;
        justify-content: flex-end;
        background-size: cover;
    }
    section.invert {
        background-image: url('../_template/style/pnc_logo_typeA_invert_alpha.svg');
    }
    section.title {
        background-position: 0% 0%;
        background-size: 500px;
    }
    section.title, section.invert {
        justify-content: center;
        text-align: center;
        font-size: 250%;
    }
    section.title::after, section.invert::after {
        display: none;
    }
    ul,ol {
        text-align: left;
    }
    footer {
        left: 70pt;
        right: 70pt;
        text-align: center;
    }
    /* === Custom style === */
    div.twocolumn {
        column-count: 2;
    }
    strong {
        color: red;
        font-style: normal;
        font-weight: bold;
    }
    /* You can add whatever style here */
---
<!-- _class: invert title -->

# @@@ PUT TITLE HERE @@@

Phish'n'Chips Team

---

## @@@ Sample slide 1 @@@

- ...
    - ...

```python
def main():
    s = "This is a sample for code"
    print(s)
```

---

## @@@ Sample slide 2 @@@

<!-- this will create two column layout (you need to enable HTML) -->
<div class=twocolumn>

- ...
    - ...
    - ...
    - ...

- ...
    - ...
    - ...
    - ...

</div>

---
<!-- _class: invert -->

These slides are licensed under Create Commons
Attribution 4.0 International License (CC-BY 4.0)
<img src="https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/by.svg" width="400" alt="CC-BY License" /><!-- see https://creativecommons.org/about/downloads/ for logo -->

Created/Modified by:
- @@@ 20XX: PUT YOUR NAME HERE @@@
