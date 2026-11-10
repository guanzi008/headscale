package db

import (
	"reflect"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// UseGlobalIDs preserves opaque user and node identities when multiple private
// databases share one control URL. Existing IDs are retained.
func (hsdb *HSDatabase) UseGlobalIDs(allocate func(string) (uint64, error)) error {
	assign := func(tx *gorm.DB) {
		if tx.Statement.Schema == nil {
			return
		}
		kind := ""
		switch tx.Statement.Schema.ModelType {
		case reflect.TypeFor[types.User]():
			kind = "user"
		case reflect.TypeFor[types.Node]():
			kind = "node"
		default:
			return
		}
		field := tx.Statement.Schema.LookUpField("ID")
		if field == nil {
			return
		}
		set := func(value reflect.Value) {
			if !value.IsValid() || value.Kind() == reflect.Pointer && value.IsNil() {
				return
			}
			value = reflect.Indirect(value)
			if value.Kind() != reflect.Struct {
				tx.AddError(gorm.ErrInvalidData)
				return
			}
			if _, zero := field.ValueOf(tx.Statement.Context, value); !zero {
				return
			}
			id, err := allocate(kind)
			if err == nil {
				err = field.Set(tx.Statement.Context, value, id)
			}
			if err != nil {
				tx.AddError(err)
			}
		}
		value := tx.Statement.ReflectValue
		if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
			for i := 0; i < value.Len(); i++ {
				set(value.Index(i))
			}
		} else {
			set(value)
		}
	}
	callbacks := hsdb.DB.Callback().Create()
	if callbacks.Get("headscale:console-identities") != nil {
		return callbacks.Replace("headscale:console-identities", assign)
	}
	return callbacks.Before("gorm:create").Register("headscale:console-identities", assign)
}
