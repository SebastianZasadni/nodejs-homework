const express = require('express')
const router = express.Router()
const Joi = require('joi')
const Contact = require('../models/contact.js')
const auth = require('../middleware/auth.js')

const contactSchema = Joi.object({
    name: Joi.string(),
    email: Joi.string(),
    phone: Joi.string(),
    favorite: Joi.boolean(),
});

router.get('/', auth, async (req, res, next) => {
    try {
        const { _id: owner } = req.user;
        const contacts = await Contact.find({ owner }, "-createdAt -updatedAt");
        res.status(200).json(
            {
                status: "success",
                data: contacts,
            });
    } catch (error) {
        next(error)
    }
})

router.get('/:id', auth, async (req, res, next) => {
    try {
        const { id } = req.params;
        const { _id: owner } = req.user;
        const contacts = await Contact.find({ owner }, "-createdAt -updatedAt");
        const contact = contacts && contacts.filter(contact => contact.id === id);
        if (!contact.length) {
            throw new Error('Contact not found')
        }
        res.status(200).json(
            {
                status: "success",
                data: contact,
            });
    } catch (error) {
        res.status(400).json({
            status: "error",
            data: {
                message: error.message,
            }
        })
    }
})

router.post('/', auth, async (req, res, next) => {
    try {
        const { name, phone, email } = req.body;
        const favorite = false;
        const validate = contactSchema.validate({
            name, phone, email, favorite
        });
        validate.error && res.status(400).json({
            status: "failed",
            message: validate.error.message
        });
        const { _id: owner } = req.user;
        const newContact = await Contact.create({ name, phone, email, favorite, owner })
        res.status(201).json({
            status: "success",
            data: newContact
        });
    } catch (error) {
        next(error);
    }

})

router.put('/:id', auth, async (req, res, next) => {
    try {
        const { body } = req;
        const { id } = req.params;
        const { _id: owner } = req.user;
        const validate = contactSchema.validate(
            body
        );
        validate.error && res.status(400).json({
            status: "failed",
            message: validate.error.message
        });
        const contacts = await Contact.find({ owner }, "-createdAt -updatedAt");
        const contact = contacts.filter(contact => contact.id === id);
        if (!contact.length) {
            throw new Error('Contact not found')
        }
        const updatedContact = await Contact.findByIdAndUpdate(
            id,
            body,
            { new: true });
        if (!updatedContact) {
            throw new Error('Contact not found')
        };
        res.status(201).json({
            status: "success",
            message: 'Contact updated',
            data: updatedContact
        })
    } catch (error) {
        console.log(error)
        next(error);
    }

})

router.delete('/:id', auth, async (req, res, next) => {
    try {
        const { id } = req.params;
        const { _id: owner } = req.user;
        const contacts = await Contact.find({ owner }, "-createdAt -updatedAt");
        const contact = contacts.filter(contact => contact.id === id);
        if (!contact.length) {
            throw new Error('Contact not found')
        }
        const deletedContact = await Contact.findByIdAndRemove(id);
        if (!deletedContact) {
            throw new Error('Contact not found')
        }
        res.status(200).json({
            status: "success",
            message: "Contact deleted",
            data: deletedContact
        })
    } catch (error) {
        next(error);
    }
})

router.patch('/:id/favorite', auth, async (req, res, next) => {
    try {
        const { id } = req.params;
        const { favorite } = req.body;
        if (!favorite) {
            return res.status(404).json({
                message: "Missing field favorite"
            })
        }
        const updatedContact = await Contact.findByIdAndUpdate(id, { favorite }, {
            new: true
        })
        if (updatedContact) {
            return res.status(200).json({
                status: "success",
                message: "Contact updated",
                data: updatedContact
            })
        }
        return res.status(404).json({
            status: "failed",
            message: "Contact not found"
        });
    } catch (error) {
        next(error);
    }
})


module.exports = router


