class Modal {
    constructor(modalId) {
        console.log(modalId)
        this.modal = document.getElementById(modalId);
    }
    open() {
        this.modal.classList.remove('hidden');
    }
    close() {
        this.modal.classList.add('hidden');
    }
}

class ModalWithForm extends Modal {
    constructor(modalId, name, formActionAdd, formActionEdit) {
        super(modalId);
        this.name = name;
        this.form = this.modal.querySelector('#modalForm');
        this.formActionAdd = formActionAdd;
        this.formActionEdit = formActionEdit;
        this.modalTitle = this.modal.querySelector('#modalTitle');
        this.actionButton = this.modal.querySelector('#actionButton');
        this.cancelButton = this.modal.querySelector('#cancelButton');
        this.imagePreview = this.modal.querySelector('#previewImg');

        this.handleEvents();
    }

    handleEvents() {
        if (this.cancelButton) {
            this.cancelButton.addEventListener('click', (e) => {
                e.preventDefault();
                this.close();
            });
        }
    }

    open(data = null) {
        if (data) {
            this.form.action = `${this.formActionEdit}/${data.id}`;
            this.modalTitle.innerText = `Edit ${this.name}`;
            this.actionButton.innerText = 'Update';

            Object.keys(data).forEach((key) => {
                const input = this.modal.querySelector(`[name="${key}"]`);
                if (input) {
                    input.value = data[key] || '';
                }
            });

            if (data.imageUrl) {
                this.imagePreview.src = data.imageUrl;
                this.imagePreview.classList.remove('hidden');
            }
        } else {
            this.form.reset();
            this.form.action = this.formActionAdd;
            this.modalTitle.innerText = `New ${this.name}`;
            this.imagePreview && this.imagePreview.classList.add('hidden');
        }

        super.open();
    }

    close() {
        super.close();
        this.form.reset();
    }
}