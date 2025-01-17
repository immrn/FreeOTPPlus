package org.fedorahosted.freeotp.ui

import android.bluetooth.le.ScanResult
import android.os.Build
import android.view.View
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import kotlinx.android.synthetic.main.row_scan_result.view.device_alias
import org.fedorahosted.freeotp.databinding.RowScanResultBinding
import org.fedorahosted.freeotp.R
import kotlinx.android.synthetic.main.row_scan_result.view.device_name
import kotlinx.android.synthetic.main.row_scan_result.view.mac_address
import kotlinx.android.synthetic.main.row_scan_result.view.signal_strength

// import org.jetbrains.anko.layoutInflater

class ScanResultAdapter(
    private val items: List<ScanResult>,
    private val onClickListener: ((device: ScanResult) -> Unit)

) : RecyclerView.Adapter<ScanResultAdapter.ViewHolder>() {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        // binding = RowScanResultBinding.inflate(LayoutInflater.from(parent.context))
        //setContentView(binding.root)
        // val view = parent.context.layoutInflater.inflate(
        val view = LayoutInflater.from(parent.context).inflate(
            R.layout.row_scan_result,
            parent,
            false
        )
        return ViewHolder(view, onClickListener)
    }

    override fun getItemCount() = items.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.bind(item)
    }

    class ViewHolder(
        private val view: View,
        private val onClickListener: ((device: ScanResult) -> Unit)
    ) : RecyclerView.ViewHolder(view) {

        fun bind(result: ScanResult) {
            view.device_name.text = result.device.name ?: "Unnamed"
            view.mac_address.text = result.device.address
            view.signal_strength.text = "${result.rssi} dBm"
            view.setOnClickListener { onClickListener.invoke(result) }
        }
    }
}