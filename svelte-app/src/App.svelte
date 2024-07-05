<script>
  // Aquí puedes agregar cualquier lógica de JavaScript que necesites
</script>

<style>
  .all {
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh; /* Ocupa toda la altura de la pantalla */
    width: 100vw; /* Ocupa toda la anchura de la pantalla */
    padding: 20px; /* Añade un poco de padding para evitar que el contenido toque los bordes */
    box-sizing: border-box;
  }

  .btn-items, .btn-add, .btn-settings {
    margin-bottom: 15px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .image {
    width: 100%;
    max-width: 370px;
    height: auto;
    object-fit: contain;
  }

  .image-container {
    display: flex;
    justify-content: center;
    align-items: center;
    width: 100%;
  }

  .content {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    width: 100%;
    max-width: 440px;
    background-color: #f5f5f5;
    border-radius: 10px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    padding: 20px;
    box-sizing: border-box;
    margin: 0 auto;
  }

  button {
    align-items: center;
    appearance: none;
    background-color: rgb(164, 189, 206);
    border-radius: 24px;
    border-style: none;
    box-shadow: rgba(0, 0, 0, 0.605) 0 3px 5px -1px, rgba(0, 0, 0, 0.605) 0 6px 10px 0, rgba(0, 0, 0, 0.605) 0 1px 18px 0;
    box-sizing: border-box;
    color: #123B5A;
    cursor: pointer;
    display: inline-flex;
    fill: currentcolor;
    font-family: "Bowlby One", sans-serif;
    font-style: normal;
    font-size: 25px;
    font-weight: bold;
    height: 48px;
    justify-content: center;
    line-height: normal;
    /* max-width: 100%; */
    overflow: visible;
    padding: 2px 24px;
    position: relative;
    text-align: center;
    text-transform: none;
    transition: box-shadow 280ms cubic-bezier(.4, 0, .2, 1), opacity 15ms linear 30ms, transform 270ms cubic-bezier(0, 0, .2, 1) 0ms;
    transition: 290ms ease-in-out;
    user-select: none;
    -webkit-user-select: none;
    touch-action: manipulation;
    width: 350px;
    will-change: transform, opacity;
    z-index: 0;
  }

  button:hover {
    background: #001f3f;
    color: rgb(164, 189, 206);
  }

  button:active {
    box-shadow: 0 4px 4px 0 rgba(18, 59, 90, 0.497), 0 8px 12px 6px rgba(18, 59, 90, 0.53);
    outline: none;
  }

  button:focus {
    outline: none;
    border: 2px solid  rgb(164, 189, 206);
  }

  button:not(:disabled) {
    box-shadow: rgba(60, 64, 67, .3) 0 1px 3px 0, rgba(60, 64, 67, .15) 0 4px 8px 3px;
  }

  button:not(:disabled):hover {
    box-shadow: rgba(60, 64, 67, .3) 0 2px 3px 0, rgba(60, 64, 67, .15) 0 6px 10px 4px;
  }

  button:not(:disabled):focus {
    box-shadow: rgba(60, 64, 67, .3) 0 1px 3px 0, rgba(60, 64, 67, .15) 0 4px 8px 3px;
  }

  button:not(:disabled):active {
    box-shadow: rgba(60, 64, 67, .3) 0 4px 4px 0, rgba(60, 64, 67, .15) 0 8px 12px 6px;
  }

  button:disabled {
    box-shadow: rgba(60, 64, 67, .3) 0 1px 3px 0, rgba(60, 64, 67, .15) 0 4px 8px 3px;
  }

  @media (max-width: 600px) {
    .content {
      width: 100%;
      height: auto;
      padding: 10px;
      margin: 0 10px;
    }

    button {
      font-size: 35px;
      padding: 2px 16px;
    }
  }
</style>

<div class="all">
  <div class="content">
    <div class="image-container">
      <img class="image" src="/static/images/StockFlow.png" alt="StockFlow">
    </div>
    <div class="all-buttons">
      <div class="btn-add">
        <a href="/add_product">
          <button>Add Item</button>
        </a>
      </div>
      <div class="btn-items">
        <a href="/view_items">
          <button>Items</button>
        </a>
      </div>
      <div class="btn-settings">
        <a href="/settings">
          <button>Settings</button>
        </a>
      </div>
    </div>
  </div>
</div>